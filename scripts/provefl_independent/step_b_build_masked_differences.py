#!/usr/bin/env python3
"""Step B: each chunk's designated owner alone constructs Enc(u_i-u_j+sum_s B_s)."""
import argparse
from common import *
def main():
    p=argparse.ArgumentParser(); p.add_argument('--server-id',type=int,required=True,choices=range(NUM_SERVERS)); p.add_argument('--overwrite',action='store_true'); add_scope_args(p); a=p.parse_args()
    work=[t for t in selected_work(a) if chunk_owner(t[2])==a.server_id]
    if not work: print(f'Server {a.server_id}: no chunks in requested scope'); return
    from openfhe import DeserializeCiphertext
    cc,pk,load,serialize,BINARY=load_openfhe()
    for n,(i,j,k) in enumerate(work,1):
        out=masked_ct_path(i,j,k)
        if out.exists() and not a.overwrite: raise FileExistsError(f'{out} exists; use --overwrite only for a full downstream restart')
        left=load(DeserializeCiphertext,client_chunk_path(i,k)); right=load(DeserializeCiphertext,client_chunk_path(j,k))
        masked=cc.EvalSub(left,right)
        for s in range(NUM_SERVERS): masked=cc.EvalAdd(masked,load(DeserializeCiphertext,mask_ct_path(s,i,j,k)))
        out.parent.mkdir(parents=True,exist_ok=True)
        if not serialize(str(out),masked,BINARY): raise RuntimeError(f'Could not serialize {out}')
        if n%100==0: print(f'owner server {a.server_id}: {n}/{len(work)}')
    print(f'Server {a.server_id}: constructed {len(work)} masked ciphertexts for chunks it owns.')
if __name__=='__main__': main()
