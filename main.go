package main

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/pgeth"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/redis/go-redis/v9"
)

type MonitoringEngine struct {
	ptk *pgeth.PluginToolkit

	backend     *eth.EthAPIBackend
	chainConfig *params.ChainConfig
	coinbase    common.Address
	state       *state.StateDB
	header      *types.Header

	latestBlock *types.Block

	errChan chan error

	rdb *redis.Client
}

func NewMonitoringEngine(pt *pgeth.PluginToolkit, rdb *redis.Client, errChan chan error) *MonitoringEngine {

	return &MonitoringEngine{
		ptk:         pt,
		backend:     pt.Backend.(*eth.EthAPIBackend),
		chainConfig: pt.Backend.ChainConfig(),
		errChan:     errChan,
		rdb:         rdb,
	}
}

type Action interface {
	Type() string
	Children() []Action
	Parent() Action
	Depth() int
	Log()
	Has(string) bool
	Context() common.Address
	Code() common.Address

	AddChildren(Action)
}

type Call struct {
	parent Action
	depth  int

	callType string
	children []Action

	context          common.Address
	code             common.Address
	forwardedContext common.Address
	forwardedCode    common.Address

	from  common.Address
	to    common.Address
	value *big.Int
	in    []byte
	out   []byte
}

func (c *Call) Type() string {
	return c.callType
}

func (c *Call) Children() []Action {
	return c.children
}

func (c *Call) Context() common.Address {
	return c.context
}

func (c *Call) Code() common.Address {
	return c.code
}

func (c *Call) Depth() int {
	return c.depth
}

func (c *Call) Parent() Action {
	return c.parent
}

func (c *Call) AddChildren(a Action) {
	c.children = append(c.children, a)
}

func (c *Call) Log() {
	fmt.Printf("%s- %s %s to %s (%s:%s) (%d,%d) (%d)\n", strings.Repeat(" ", c.depth), c.Type(), c.from.String(), c.to.String(), c.Context().String(), c.Code().String(), len(c.in), len(c.out), len(c.children))
	for _, subcall := range c.children {
		subcall.Log()
	}
}

func (c *Call) Has(typ string) bool {
	if c.Type() == typ {
		return true
	}
	for _, chld := range c.children {
		if chld.Has(typ) {
			return true
		}
	}
	return false
}

type Event struct {
	parent Action
	depth  int

	logType string

	context common.Address
	code    common.Address

	data   []byte
	topics []common.Hash
	from   common.Address
}

func (c *Event) Type() string {
	return c.logType
}

func (c *Event) Children() []Action {
	return []Action{}
}

func (c *Event) Context() common.Address {
	return c.context
}

func (c *Event) Code() common.Address {
	return c.code
}

func (c *Event) Depth() int {
	return c.depth
}

func (c *Event) Parent() Action {
	return c.parent
}

func (c *Event) AddChildren(a Action) {
}

func (c *Event) Log() {
	fmt.Printf("%s- %s (%s:%s) \n", strings.Repeat(" ", c.depth), c.Type(), c.Context().String(), c.Code().String())
}

func (c *Event) Has(typ string) bool {
	return c.Type() == typ
}

type Revert struct {
	parent Action
	depth  int

	errorType string

	context common.Address
	code    common.Address

	data []byte
	from common.Address
}

func (r *Revert) Type() string {
	return r.errorType
}

func (r *Revert) Children() []Action {
	return []Action{}
}

func (r *Revert) Context() common.Address {
	return r.context
}

func (r *Revert) Code() common.Address {
	return r.code
}

func (r *Revert) Depth() int {
	return r.depth
}

func (r *Revert) Parent() Action {
	return r.parent
}

func (r *Revert) AddChildren(a Action) {
}

func (r *Revert) Log() {
	fmt.Printf("%s- %s (%s:%s) %x\n", strings.Repeat(" ", r.depth), r.Type(), r.Context().String(), r.Code().String(), r.data)
}

func (r *Revert) Has(typ string) bool {
	return r.Type() == typ
}

type MonitoringTracer struct {
	action Action
	cursor Action
}

func (m *MonitoringTracer) Clear() {
	m.action = nil
	m.cursor = nil
}

func (m *MonitoringTracer) CaptureTxStart(gasLimit uint64) {

}
func (m *MonitoringTracer) CaptureTxEnd(restGas uint64) {

}
func (m *MonitoringTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	copyInput := make([]byte, len(input))
	copy(copyInput, input)
	m.action = &Call{
		callType: "initial_call",
		children: []Action{},
		parent:   nil,
		depth:    0,

		context: common.Address{},
		code:    common.Address{},

		forwardedContext: to,
		forwardedCode:    to,

		from:  from,
		to:    to,
		in:    copyInput,
		value: value,
	}
	m.cursor = m.action
}

func (m *MonitoringTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	copyOutput := make([]byte, len(output))
	copy(copyOutput, output)
	m.cursor.(*Call).out = copyOutput
}

func callOpcodeToString(c vm.OpCode) string {
	switch c {
	case 241:
		return "call"
	case 244:
		return "delegatecall"
	case 250:
		return "staticcall"
	default:
		return fmt.Sprintf("unknown %d", c)
	}
}

func parentContextAndCode(p Action) (common.Address, common.Address) {
	if p != nil {
		return p.(*Call).forwardedContext, p.(*Call).forwardedCode
	}
	return common.Address{}, common.Address{}
}

func (m *MonitoringTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	callType := callOpcodeToString(typ)
	ctx, code := parentContextAndCode(m.cursor)
	forwardedCode := to
	forwardedContext := to
	if callType == "delegatecall" {
		forwardedContext = from
	}
	copyInput := make([]byte, len(input))
	copy(copyInput, input)
	call := &Call{
		callType: callType,
		children: []Action{},
		parent:   m.cursor,
		depth:    m.cursor.Depth() + 1,

		forwardedContext: forwardedContext,
		forwardedCode:    forwardedCode,
		context:          ctx,
		code:             code,
		from:             from,
		to:               to,
		in:               copyInput,
		value:            value,
	}
	m.cursor.AddChildren(call)
	m.cursor = call
}

func (m *MonitoringTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	copyOutput := make([]byte, len(output))
	copy(copyOutput, output)
	m.cursor.(*Call).out = copyOutput
	m.cursor = m.cursor.Parent()
}

func addZeros(arr []byte, zeros int64) []byte {
	return append(arr, make([]byte, zeros)...)
}

func (m *MonitoringTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if op >= 160 && op <= 164 {
		stack := scope.Stack.Data()
		stackLen := len(stack)
		offset := stack[stackLen-1].ToBig().Int64()
		size := stack[stackLen-2].ToBig().Int64()
		fetchSize := size
		var data []byte = []byte{}
		if int64(scope.Memory.Len()) < offset {
			fetchSize = 0
			// generate zero array
		} else if int64(scope.Memory.Len()) < offset+size {
			fetchSize -= (offset + size) - int64(scope.Memory.Len())
		}

		if fetchSize > 0 {
			data = scope.Memory.GetCopy(offset, fetchSize)
		}

		if fetchSize < size {
			data = addZeros(data, size-fetchSize)
		}

		topics := []common.Hash{}
		for idx := 0; idx < int(op-160); idx++ {
			topics = append(topics, stack[stackLen-3-idx].Bytes32())
		}

		ctx, code := parentContextAndCode(m.cursor)

		m.cursor.AddChildren(&Event{
			logType: fmt.Sprintf("log%d", op-160),
			data:    data,
			topics:  topics,
			from:    scope.Contract.Address(),

			context: ctx,
			code:    code,
			parent:  m.cursor,
			depth:   m.cursor.Depth() + 1,
		})
	}
	if op == 253 {
		errorType := "revert"
		data := []byte{}
		stack := scope.Stack.Data()
		stackLen := len(stack)
		offset := stack[stackLen-1].ToBig().Int64()
		size := stack[stackLen-2].ToBig().Int64()
		fetchSize := size
		if int64(scope.Memory.Len()) < offset {
			fetchSize = 0
			// generate zero array
		} else if int64(scope.Memory.Len()) < offset+size {
			fetchSize -= (offset + size) - int64(scope.Memory.Len())
		}

		if fetchSize > 0 {
			data = scope.Memory.GetCopy(offset, fetchSize)
		}

		if fetchSize < size {
			data = addZeros(data, size-fetchSize)
		}

		ctx, code := parentContextAndCode(m.cursor)

		m.cursor.AddChildren(&Revert{
			errorType: errorType,
			data:      data,
			from:      scope.Contract.Address(),
			context:   ctx,
			code:      code,
			parent:    m.cursor,
			depth:     m.cursor.Depth() + 1,
		})
	}
}

func (m *MonitoringTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	if op != 253 {
		ctx, code := parentContextAndCode(m.cursor)
		m.cursor.AddChildren(&Revert{
			errorType: "panic",
			data:      []byte{},
			from:      scope.Contract.Address(),
			context:   ctx,
			code:      code,
			parent:    m.cursor,
			depth:     m.cursor.Depth() + 1,
		})
	}
}

func (me *MonitoringEngine) update(ctx context.Context, parent *types.Block) {

	state, _, err := me.backend.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithHash(parent.Hash(), true))
	if err != nil {
		me.errChan <- err
		return
	}
	me.header = &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number(), common.Big1),
		GasLimit:   parent.GasLimit(),
		Time:       parent.Time() + 12,
		Coinbase:   parent.Coinbase(),
		BaseFee:    misc.CalcBaseFee(me.chainConfig, parent.Header()),
		Difficulty: parent.Difficulty(),
	}
	me.coinbase = parent.Coinbase()
	me.state = state
}

func callTypeToPrefix(c *Call) string {
	switch c.Type() {
	case "call":
		return "C"
	case "staticcall":
		return "S"
	case "delegatecall":
		return "D"
	case "initial_call":
		return "C"
	}
	return "X"
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func encodeSelector(c *Call) string {
	selector := fmt.Sprintf("%x", c.in[0:minInt(4, len(c.in))])
	for len(selector) < 8 {
		selector += "X"
	}
	return selector
}

func encodeActionCalls(a Action) string {
	res := ""
	if c, ok := a.(*Call); ok {
		prefix := callTypeToPrefix(c)
		selector := encodeSelector(c)
		res = fmt.Sprintf("%s@%s_%s", prefix, c.to.String(), selector)
		if len(a.Children()) > 0 {
			chldArr := []string{}
			for _, chld := range a.Children() {
				chldRes := encodeActionCalls(chld)
				if len(chldRes) > 0 {
					chldArr = append(chldArr, chldRes)
				}
			}
			if len(chldArr) > 0 {
				joinedChldRes := strings.Join(chldArr[:], ",")
				res = fmt.Sprintf("%s[%s]", res, joinedChldRes)
			}
		}
	}

	return res
}

func (me *MonitoringEngine) encodeAndBroadcastCallTrace(ctx context.Context, at *AnalyzedTransaction, channel string) {
	var topic string
	if at.Transaction.To() == nil {
		topic = fmt.Sprintf("/%s/tx/%s/%s/null/%s", channel, at.Transaction.Hash(), at.From, encodeActionCalls(at.Traces))
	} else {
		topic = fmt.Sprintf("/%s/tx/%s/%s/%s/%s", channel, at.Transaction.Hash(), at.From, at.Transaction.To(), encodeActionCalls(at.Traces))

	}

	err := me.rdb.Publish(ctx, topic, "OK").Err()
	if err != nil {
		me.errChan <- err
	}

	err = me.rdb.Expire(ctx, topic, 1*time.Hour).Err()
	if err != nil {
		me.errChan <- err
	}
}

func (me *MonitoringEngine) encodeAndBroadcast(ctx context.Context, ats []AnalyzedTransaction, channel string) {
	for _, analyzedTx := range ats {
		me.encodeAndBroadcastCallTrace(ctx, &analyzedTx, channel)
	}
}

type AnalyzedTransaction struct {
	Transaction *types.Transaction
	From        common.Address
	Receipt     *types.Receipt
	Traces      Action
}

func (me *MonitoringEngine) analyze(ctx context.Context, block *types.Block) {
	// simulate all block here
	parentBlk, err := me.backend.BlockByHash(ctx, block.ParentHash())
	if err != nil {
		me.errChan <- err
		return
	}
	state, _, err := me.backend.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithHash(parentBlk.Hash(), true))
	if err != nil {
		me.errChan <- err
		return
	}
	gp := new(core.GasPool).AddGas(block.Header().GasLimit)
	mt := MonitoringTracer{}
	var vmConfig vm.Config = vm.Config{
		Debug:                   true,
		Tracer:                  &mt,
		NoBaseFee:               false,
		EnablePreimageRecording: false,
		ExtraEips:               []int{},
	}
	analyzedTransactions := []AnalyzedTransaction{}
	for _, tx := range block.Transactions() {
		receipt, err := core.ApplyTransaction(me.chainConfig, me.backend.Ethereum().BlockChain(), &block.Header().Coinbase, gp, state, block.Header(), tx, &block.Header().GasUsed, vmConfig)
		if err != nil {
			me.errChan <- err
			return
		}
		signer := types.MakeSigner(me.backend.Ethereum().BlockChain().Config(), receipt.BlockNumber)
		msg, err := tx.AsMessage(signer, nil)
		if err != nil {
			me.errChan <- err
			return
		}
		analyzedTransactions = append(analyzedTransactions, AnalyzedTransaction{
			Transaction: tx,
			From:        msg.From(),
			Receipt:     receipt,
			Traces:      mt.action,
		})
		mt.Clear()
	}
	me.ptk.Logger.Info("Simulated txs", "count", len(block.Transactions()))
	me.encodeAndBroadcast(ctx, analyzedTransactions, "head")
	me.ptk.Logger.Info("Broadcasted txs", "count", len(block.Transactions()))
	me.latestBlock = block
}

func (me *MonitoringEngine) analyzePending(ctx context.Context, txs []*types.Transaction) {
	// simulate all block here
	if me.header == nil {
		me.ptk.Logger.Warn("Skipping pending tx simulation, not ready")
		return
	}
	gp := new(core.GasPool).AddGas(me.header.GasLimit)
	mt := MonitoringTracer{}
	var vmConfig vm.Config = vm.Config{
		Debug:                   true,
		Tracer:                  &mt,
		NoBaseFee:               false,
		EnablePreimageRecording: false,
		ExtraEips:               []int{},
	}
	analyzedTransactions := []AnalyzedTransaction{}
	for _, tx := range txs {
		receipt, err := core.ApplyTransaction(me.chainConfig, me.backend.Ethereum().BlockChain(), &me.header.Coinbase, gp, me.state, me.header, tx, &me.header.GasUsed, vmConfig)
		if err != nil {
			continue
		}
		signer := types.MakeSigner(me.backend.Ethereum().BlockChain().Config(), receipt.BlockNumber)
		msg, err := tx.AsMessage(signer, nil)
		if err != nil {
			me.errChan <- err
			return
		}
		analyzedTransactions = append(analyzedTransactions, AnalyzedTransaction{
			Transaction: tx,
			From:        msg.From(),
			Receipt:     receipt,
			Traces:      mt.action,
		})
		mt.Clear()
	}
	if len(analyzedTransactions) > 0 {
		me.encodeAndBroadcast(ctx, analyzedTransactions, "pending")
	}
}

func (me *MonitoringEngine) startHeadListener(ctx context.Context) {
	headChan := make(chan core.ChainHeadEvent)
	headSubscription := me.backend.SubscribeChainHeadEvent(headChan)
	pendingChan := make(chan core.NewTxsEvent)
	pendingSubscription := me.backend.SubscribeNewTxsEvent(pendingChan)
	ticker := time.NewTicker(30 * time.Second)
	analyzedPendingTxs := 0

	defer headSubscription.Unsubscribe()
	defer pendingSubscription.Unsubscribe()
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-headSubscription.Err():
			if err != nil {
				me.errChan <- err
			}
			return
		case err := <-pendingSubscription.Err():
			if err != nil {
				me.errChan <- err
			}
			return
		case newHead := <-headChan:
			me.update(ctx, newHead.Block)
			me.ptk.Logger.Info("Head was updated", "number", newHead.Block.NumberU64(), "hash", newHead.Block.Hash(), "root", newHead.Block.Root())

			me.analyze(ctx, newHead.Block)
		case newTxs := <-pendingChan:
			me.analyzePending(ctx, newTxs.Txs)
			analyzedPendingTxs += len(newTxs.Txs)
		case <-ticker.C:
			if analyzedPendingTxs > 0 {
				me.ptk.Logger.Info("Analyzed pending txs", "count", analyzedPendingTxs, "rate", fmt.Sprintf("%f/s", float64(analyzedPendingTxs)/float64(30)))
				analyzedPendingTxs = 0
			}
		}
	}
}

func (me *MonitoringEngine) Start(ctx context.Context) {
	me.startHeadListener(ctx)
}

func Start(pt *pgeth.PluginToolkit, cfg map[string]interface{}, ctx context.Context, errChan chan error) {
	var redisEndpointRaw interface{}
	var redisEndpoint string
	var ok bool

	if redisEndpointRaw, ok = cfg["REDIS_ENDPOINT"]; !ok {
		pt.Logger.Error("missing REDIS_ENDPOINT config var")
		return
	}

	if redisEndpoint, ok = redisEndpointRaw.(string); !ok {
		pt.Logger.Error("invalid REDIS_ENDPOINT value")
		return
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisEndpoint,
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	me := NewMonitoringEngine(pt, rdb, errChan)

	me.Start(ctx)

}
