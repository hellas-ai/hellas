"""Write the small decision-model GGUF behind the `mini-d1` descriptor fixture.

Tensor data is deliberately zero. The fixture keeps only the header:

    python3 make_mini_d1_gguf.py full.gguf && hellas model describe full.gguf -o mini-d1
"""
import struct
import sys

def u32(n): return struct.pack('<I',n)
def u64(n): return struct.pack('<Q',n)
def f32(x): return struct.pack('<f',x)
def string(s):
 b=s.encode(); return u64(len(b))+b
def metadata(key,kind,value): return string(key)+u32(kind)+value
def array(kind,values): return u32(kind)+u64(len(values))+b''.join(values)

# One attention block, at the smallest widths the
# LFM3 kernels accept.
H,FF,HEADS,HEAD,KERNEL=256,256,8,128,7
kv_heads=[HEADS]
controls=['<|startoftext|>','<|im_start|>','<|im_end|>','<|image|>']
tokens=[chr(c) for c in range(33,127)]+['Ċ','Ġ','yes','no']+controls
TEMPLATE=("<|startoftext|><|im_start|>{{ state if state is string else state | tojson }}\n"
 "{{ instructions }}{% for o in options %}\n{{ o.label }} {{ o.key }}{% endfor %}<|im_end|>")
meta=[metadata('general.architecture',8,string('lfm3')),metadata('general.name',8,string('keyhole-mini-d1'))]
for key,value in [('block_count',len(kv_heads)),('context_length',128),('embedding_length',H),('feed_forward_length',FF),('attention.head_count',HEADS),('attention.key_length',HEAD),('rope.dimension_count',HEAD),('attention.sliding_window',16),('shortconv.l_cache',KERNEL)]:
 meta.append(metadata('lfm3.'+key,4,u32(value)))
for key,value in [('attention.layer_norm_rms_epsilon',1e-5),('rope.freq_base',1e6),('rope.freq_base_swa',1e4)]: meta.append(metadata('lfm3.'+key,6,f32(value)))
meta += [metadata('lfm3.attention.head_count_kv',9,array(5,[struct.pack('<i',n) for n in kv_heads])),
 metadata('lfm3.attention.sliding_window_pattern',9,array(7,[b'\0' for _ in kv_heads])),
 metadata('lfm3.attention.causal',7,b'\0'),
 metadata('lfm3.decision.type',8,string('lfm3-d1'))]
for kind in ['noul','choice','score']: meta.append(metadata('lfm3.decision.temperature.'+kind,6,f32(1.5)))
meta += [metadata('tokenizer.ggml.model',8,string('gpt2')),metadata('tokenizer.ggml.pre',8,string('lfm2')),
 metadata('tokenizer.ggml.tokens',9,array(8,[string(s) for s in tokens])),
 metadata('tokenizer.ggml.token_type',9,array(5,[struct.pack('<i',3 if s in controls else 1) for s in tokens])),
 metadata('tokenizer.ggml.merges',9,array(8,[string('n o')])),
 metadata('tokenizer.ggml.bos_token_id',4,u32(tokens.index('<|startoftext|>'))),
 metadata('tokenizer.ggml.eos_token_id',4,u32(tokens.index('<|im_end|>'))),
 metadata('tokenizer.ggml.add_bos_token',7,b'\0'),metadata('tokenizer.ggml.add_eos_token',7,b'\0'),
 metadata('tokenizer.chat_template.systemone',8,string(TEMPLATE))]
BF16,F32=30,0
tensors=[('token_embd.weight',[len(tokens),H],BF16),('output_norm.weight',[H],F32),('rope_freqs.weight',[HEAD//2],F32)]
for layer,heads in enumerate(kv_heads):
 block=[(name,[H],F32) for name in ['attn_norm','post_attention_norm','ffn_norm','post_ffw_norm']]
 block += [('ffn_gate',[FF,H],BF16),('ffn_up',[FF,H],BF16),('ffn_down',[H,FF],BF16)]
 if heads == 0:
  block += [('shortconv.in_proj',[3*H,H],BF16),('shortconv.out_proj',[H,H],BF16),('shortconv.conv',[H,KERNEL],F32)]
 else:
  block += [('attn_q',[HEADS*HEAD,H],BF16),('attn_k',[heads*HEAD,H],BF16),('attn_v',[heads*HEAD,H],BF16),('attn_gate',[HEADS,H],BF16),('attn_output',[H,HEADS*HEAD],BF16),('attn_q_norm',[HEAD],F32),('attn_k_norm',[HEAD],F32)]
 tensors += [(f'blk.{layer}.{name}.weight',shape,dtype) for name,shape,dtype in block]
table=[]; payload=bytearray()
for name,shape,dtype in tensors:
 offset=(len(payload)+31)//32*32; payload.extend(bytes(offset-len(payload)))
 count=1
 for n in shape: count*=n
 table.append(string(name)+u32(len(shape))+b''.join(u64(n) for n in reversed(shape))+u32(dtype)+u64(offset))
 payload.extend(bytes(count*(2 if dtype==BF16 else 4)))
header=b'GGUF'+u32(3)+u64(len(tensors))+u64(len(meta))+b''.join(meta)+b''.join(table)
header += bytes((-len(header))%32)
open(sys.argv[1],'wb').write(header+payload)
