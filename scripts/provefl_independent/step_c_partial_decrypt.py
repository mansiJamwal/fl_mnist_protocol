#!/usr/bin/env python3
"""Step C1: each server emits a partial decryption for every masked ciphertext."""
import argparse
from common import *
def main():
    p=argparse.ArgumentParser(); p.add_argument('--server-id',type=int,required=True,choices=range(NUM_SERVERS)); p.add_argument('--all',action='store_true'); add_scope_args(p); a=p.parse_args()
    work=all_work() if a.all else selected_work(a)
    from openfhe import DeserializeCiphertext, DeserializePrivateKey
    cc,pk,load,serialize,BINARY=load_openfhe(); sk=load(DeserializePrivateKey,PRIVATE_DIR/f'party_{a.server_id}'/'secret_key.bin')
    for n,(i,j,k) in enumerate(work,1):
        ct=load(DeserializeCiphertext,masked_ct_path(i,j,k))
        partials=cc.MultipartyDecryptLead([ct],sk) if a.server_id==0 else cc.MultipartyDecryptMain([ct],sk)
        if not partials: raise RuntimeError(f'No partial returned for pair {i},{j}, chunk {k}')
        out=partial_path(a.server_id,i,j,k); out.parent.mkdir(parents=True,exist_ok=True)
        if not serialize(str(out),partials[0],BINARY): raise RuntimeError(f'Could not serialize {out}')
        if n%100==0: print(f'server {a.server_id}: {n}/{len(work)}')
    print(f'Server {a.server_id}: wrote {len(work)} partial decryptions.')
if __name__=='__main__': main()
