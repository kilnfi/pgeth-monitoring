package main

import (
	"context"
	"fmt"
	"math/big"
	"strings"

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
}

func NewMonitoringEngine(pt *pgeth.PluginToolkit, cfg interface{}, errChan chan error) *MonitoringEngine {
	return &MonitoringEngine{
		ptk:         pt,
		backend:     pt.Backend.(*eth.EthAPIBackend),
		chainConfig: pt.Backend.ChainConfig(),
		errChan:     errChan,
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
		in:    input,
		value: value,
	}
	m.cursor = m.action
}

func (m *MonitoringTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
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
		in:               input,
		value:            value,
	}
	m.cursor.AddChildren(call)
	m.cursor = call
}

func (m *MonitoringTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	m.cursor.(*Call).out = output
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
		Time:       parent.Time() + 1,
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
		return "I"
	}
	return "X"
}

func encodeActionCalls(a Action) string {
	res := ""
	if c, ok := a.(*Call); ok {
		prefix := callTypeToPrefix(c)
		res = fmt.Sprintf("%s@%s", prefix, c.to.String())
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

func (me *MonitoringEngine) encodeAndBroadcastCallTrace(at *AnalyzedTransaction, channel string) {
	var topic string
	if at.Transaction.To() == nil {
		topic = fmt.Sprintf("/%s/tx/%s/%s/null/%s", channel, at.Transaction.Hash(), at.From, encodeActionCalls(at.Traces))
	} else {
		topic = fmt.Sprintf("/%s/tx/%s/%s/%s/%s", channel, at.Transaction.Hash(), at.From, at.Transaction.To(), encodeActionCalls(at.Traces))

	}

	println(topic)
}

func (me *MonitoringEngine) encodeAndBroadcast(ats []AnalyzedTransaction, channel string) {
	for _, analyzedTx := range ats {
		me.encodeAndBroadcastCallTrace(&analyzedTx, channel)
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
	me.encodeAndBroadcast(analyzedTransactions, "head")
	me.latestBlock = block
}

func (me *MonitoringEngine) startHeadListener(ctx context.Context) {
	headChan := make(chan core.ChainHeadEvent)
	subscription := me.backend.SubscribeChainHeadEvent(headChan)
	for {
		select {
		case <-ctx.Done():
			subscription.Unsubscribe()
			return
		case err := <-subscription.Err():
			subscription.Unsubscribe()
			if err != nil {
				me.errChan <- err
			}
			return
		case newHead := <-headChan:
			me.update(ctx, newHead.Block)
			me.ptk.Logger.Info("Head was updated", "number", newHead.Block.NumberU64(), "hash", newHead.Block.Hash(), "root", newHead.Block.Root())

			me.analyze(ctx, newHead.Block)
		}
	}
}

func (me *MonitoringEngine) Start(ctx context.Context) {
	me.startHeadListener(ctx)
}

func Start(pt *pgeth.PluginToolkit, cfg interface{}, ctx context.Context, errChan chan error) {
	me := NewMonitoringEngine(pt, cfg, errChan)

	me.Start(ctx)

}
