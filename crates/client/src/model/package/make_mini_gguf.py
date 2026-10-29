"""Write the fixed, small CPU packaging fixture; tensor data is deliberately zero."""
from pathlib import Path
import struct

def u32(n): return struct.pack('<I',n)
def u64(n): return struct.pack('<Q',n)
def string(s):
 b=s.encode(); return u64(len(b))+b

def metadata(key,kind,value): return string(key)+u32(kind)+value
meta=[metadata('general.architecture',8,string('qwen3')),metadata('general.name',8,string('keyhole-mini'))]
for key,value in [('vocab_size',4),('embedding_length',32),('feed_forward_length',64),('block_count',1),('attention.head_count',1),('attention.head_count_kv',1),('attention.key_length',32),('context_length',128),('rope.dimension_count',32)]:
 meta.append(metadata('qwen3.'+key,4,u32(value)))
for key,value in [('attention.layer_norm_rms_epsilon',1e-6),('rope.freq_base',10000.)]: meta.append(metadata('qwen3.'+key,6,struct.pack('<f',value)))
meta += [metadata('tokenizer.ggml.model',8,string('gpt2')),metadata('tokenizer.ggml.pre',8,string('qwen2'))]
for key,values in [('tokens',['h','i','hi','<|endoftext|>']),('merges',['h i'])]: meta.append(metadata('tokenizer.ggml.'+key,9,u32(8)+u64(len(values))+b''.join(string(s) for s in values)))
meta += [metadata('tokenizer.ggml.eos_token_id',4,u32(3)),metadata('tokenizer.ggml.add_bos_token',7,b'\0'),metadata('tokenizer.ggml.add_eos_token',7,b'\0')]
tensors=[('token_embd.weight',[4,32],30),('output_norm.weight',[32],0)]
for name,shape,dtype in [('attn_norm',[32],0),('attn_q',[32,32],30),('attn_k',[32,32],30),('attn_v',[32,32],30),('attn_output',[32,32],30),('attn_q_norm',[32],0),('attn_k_norm',[32],0),('ffn_norm',[32],0),('ffn_gate',[64,32],30),('ffn_up',[64,32],30),('ffn_down',[32,64],30)]: tensors.append(('blk.0.'+name+'.weight',shape,dtype))
# Table order deliberately differs from the entry's weight argument order.
table=[]; payload=bytearray()
for name,shape,dtype in reversed(tensors):
 offset=(len(payload)+31)//32*32; payload.extend(bytes(offset-len(payload)))
 size=2 if dtype==30 else 4
 count=1
 for n in shape: count*=n
 table.append(string(name)+u32(len(shape))+b''.join(u64(n) for n in reversed(shape))+u32(dtype)+u64(offset))
 payload.extend(bytes(count*size))
header=b'GGUF'+u32(3)+u64(len(tensors))+u64(len(meta))+b''.join(meta)+b''.join(table)
header += bytes((-len(header))%32)
Path(__file__).with_name('mini-qwen3.gguf').write_bytes(header+payload)
