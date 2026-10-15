import sys,unittest,random
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "scripts" / "provefl_independent")
)

from common import Q, NUM_SERVERS

def unmask(y,betas):
 raw=y-sum(betas)
 for _ in range(NUM_SERVERS):
  if raw<0:raw+=Q
 raw%=Q
 signed=raw-Q if raw>Q//2 else raw
 return signed,(signed>0)-(signed<0)
class TestProtocolMath(unittest.TestCase):
 def test_boundaries(self):
  for d in [-1000,-2,-1,0,1,2,1000]:
   b=[(17*k+31)%Q for k in range(NUM_SERVERS)]; y=(d+sum(b))%Q; got,s=unmask(y,b); self.assertEqual(got,d); self.assertEqual(s,(d>0)-(d<0))
 def test_random(self):
  r=random.Random(17)
  for _ in range(5000):
   d=r.randint(-2000,2000); b=[r.randrange(Q) for _ in range(NUM_SERVERS)]; y=(d+sum(b))%Q; got,s=unmask(y,b); self.assertEqual(got,d); self.assertEqual(s,(d>0)-(d<0))
if __name__=='__main__':unittest.main()
