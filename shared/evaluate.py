"""Development-only evaluator of the emitted opcode subset. Not a consensus engine.

Independent node/chain-gang conformance is required; this harness is for fast
local generator tests and does not model policy, activation or resource limits.
OP_CODESEPARATOR is a no-op here. CHECKSIG callbacks select their own
scriptCode. Branching ignores the UTXO creation era, including the
post-Genesis restriction on repeated OP_ELSE.
"""
from hashlib import new, sha256
from .script import OPS, decode_num, encode_num


class ScriptError(ValueError): pass


def evaluate(raw, stack=None, checksig=None, *, observe_stack=None):
    stack=list(stack or []); alt=[]; cond=[]; i=0
    names={v:k[3:] for k,v in OPS.items()}
    def require_stack(depth):
        if len(stack) < depth:
            raise ScriptError('stack underflow')
    def pop():
        if not stack: raise ScriptError('stack underflow')
        return stack.pop()
    def num(): return decode_num(pop())
    def put(n): stack.append(encode_num(n))
    def truth(b): return decode_num(b)!=0
    try:
        while i<len(raw):
            if observe_stack is not None: observe_stack(stack, alt)
            at=i; op=raw[i]; i+=1; data=None
            if op<=78:
                n=op
                if op>=76:
                    count=1<<(op-76); n=int.from_bytes(raw[i:i+count],'little'); i+=count
                if i+n>len(raw): raise ScriptError('truncated push')
                data=raw[i:i+n]; i+=n
            active=all(cond)
            name=names.get(op)
            if name in ('IF','NOTIF'):
                cond.append((truth(pop()) ^ (name=='NOTIF')) if active else False); continue
            if name=='ELSE': cond[-1]=not cond[-1]; continue
            if name=='ENDIF': cond.pop(); continue
            if not active: continue
            if data is not None: stack.append(data); continue
            if 0x51<=op<=0x60: put(op-0x50); continue
            if name=='1NEGATE': put(-1)
            elif name=='TOALTSTACK': alt.append(pop())
            elif name=='FROMALTSTACK': stack.append(alt.pop())
            elif name=='DEPTH': put(len(stack))
            elif name=='DROP': pop()
            elif name=='2DROP': pop(); pop()
            elif name=='DUP': stack.append(stack[-1])
            elif name=='2DUP':
                require_stack(2)
                stack.extend(stack[-2:])
            elif name=='3DUP':
                require_stack(3)
                stack.extend(stack[-3:])
            elif name=='OVER': stack.append(stack[-2])
            elif name=='2OVER':
                require_stack(4)
                stack.extend(stack[-4:-2])
            elif name=='2SWAP':
                require_stack(4)
                stack[-4:] = stack[-2:] + stack[-4:-2]
            elif name=='SWAP':
                require_stack(2)
                stack[-2:] = stack[-2:][::-1]
            elif name=='ROT': stack.append(stack.pop(-3))
            elif name=='TUCK':
                require_stack(2)
                stack.insert(len(stack) - 2, stack[-1])
            elif name=='NIP': stack.pop(-2)
            elif name in ('PICK','ROLL'):
                n=num()
                if not 0<=n<len(stack): raise ScriptError('invalid stack index')
                stack.append(stack[-n-1] if name=='PICK' else stack.pop(-n-1))
            elif name=='SIZE': put(len(stack[-1]))
            elif name=='CAT': y=pop(); x=pop(); stack.append(x+y)
            elif name=='SPLIT':
                n=num(); x=pop()
                if not 0<=n<=len(x): raise ScriptError('split bounds')
                stack.extend((x[:n],x[n:]))
            elif name=='BIN2NUM': put(num())
            elif name=='NUM2BIN':
                size=num(); x=num(); value=encode_num(x)
                if size<0 or len(value)>size: raise ScriptError('number does not fit')
                if size>len(value):
                    sign=128 if x<0 else 0
                    if value: value=value[:-1]+bytes([value[-1]&127])
                    value=value+bytes(size-len(value)); value=value[:-1]+bytes([value[-1]|sign])
                stack.append(value)
            elif name in ('XOR','AND','OR'):
                y=pop(); x=pop()
                if len(x)!=len(y): raise ScriptError('bitwise length')
                stack.append(bytes((a^b if name=='XOR' else a&b if name=='AND' else a|b) for a,b in zip(x,y)))
            elif name in ('NEGATE','1ADD','1SUB','NOT','0NOTEQUAL'):
                x=num(); put(-x if name=='NEGATE' else x+1 if name=='1ADD' else x-1 if name=='1SUB' else int(x==0) if name=='NOT' else int(x!=0))
            elif name in ('ADD','SUB','MUL','DIV','MOD','MIN','MAX','BOOLAND','BOOLOR','NUMEQUAL','NUMEQUALVERIFY','LESSTHAN','GREATERTHAN'):
                y=num(); x=num()
                if name in ('DIV','MOD'):
                    q=(abs(x)//abs(y))*(-1 if (x<0) != (y<0) else 1)
                    v=q if name=='DIV' else x-q*y
                else:
                    v={'ADD':lambda:x+y,'SUB':lambda:x-y,'MUL':lambda:x*y,'MIN':lambda:min(x,y),'MAX':lambda:max(x,y),'BOOLAND':lambda:int(bool(x) and bool(y)),'BOOLOR':lambda:int(bool(x) or bool(y)),'NUMEQUAL':lambda:int(x==y),'NUMEQUALVERIFY':lambda:int(x==y),'LESSTHAN':lambda:int(x<y),'GREATERTHAN':lambda:int(x>y)}[name]()
                if name=='NUMEQUALVERIFY':
                    if not v: raise ScriptError('NUMEQUALVERIFY')
                else: put(v)
            elif name=='WITHIN': hi=num(); lo=num(); x=num(); put(int(lo<=x<hi))
            elif name in ('EQUAL','EQUALVERIFY'):
                eq=pop()==pop()
                if name=='EQUALVERIFY':
                    if not eq: raise ScriptError('EQUALVERIFY')
                else: put(int(eq))
            elif name=='VERIFY':
                if not truth(pop()): raise ScriptError('VERIFY')
            elif name in ('SHA256','HASH256','HASH160'):
                v=sha256(pop()).digest()
                stack.append(sha256(v).digest() if name=='HASH256' else new('ripemd160',v).digest() if name=='HASH160' else v)
            elif name in ('CODESEPARATOR', 'NOP'): pass
            elif name in ('CHECKSIG','CHECKSIGVERIFY'):
                key=pop(); sig=pop()
                if checksig is None: raise ScriptError('native checksig callback required')
                ok=checksig(sig,key)
                if name=='CHECKSIGVERIFY':
                    if not ok: raise ScriptError('CHECKSIGVERIFY')
                else: put(int(ok))
            else: raise ScriptError('unsupported opcode '+str(name))
        if observe_stack is not None: observe_stack(stack, alt)
        if cond: raise ScriptError('unterminated conditional')
        return stack,alt
    except (IndexError,ZeroDivisionError,ValueError) as e:
        raise ScriptError(f'{e} at byte {at} ({name})') from e
