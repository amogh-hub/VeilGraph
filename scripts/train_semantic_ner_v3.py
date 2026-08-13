#!/usr/bin/env python3
"""Development-only trainer for VeilGraph local Semantic NER v3.
Runtime inference remains pure Python and network-free."""
from __future__ import annotations
import hashlib, json, sys
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
from sklearn.linear_model import LogisticRegression

root=Path(__file__).resolve().parents[1]/'backend'; sys.path.insert(0,str(root))
from app.core.enums import EntityType
from app.detection.semantic_ner_v3 import semantic_v3_features
train_path=root/'training_data'/'semantic_ner_train_v3.json'; raw=train_path.read_bytes(); payload=json.loads(raw)
by=defaultdict(list)
for ex in payload['examples']: by[ex['entity_type']].append(ex)
out={
 'schema':'veilgraph.semantic-ner.linear.v3','version':'3.0.0',
 'model_family':'local logistic-regression contextual span classifier',
 'runtime_network_required':False,
 'training_source':'VeilGraph synthetic multi-domain semantic-context corpus v3',
 'training_corpus_sha256':hashlib.sha256(raw).hexdigest(),
 'training_examples':len(payload['examples']), 'classifiers':{}
}
thresholds={'PERSON_NAME':0.58,'EMPLOYER':0.64,'LOCALITY':0.62,'STREET_ADDRESS':0.67,'JOB_TITLE':0.67}
for et_name,items in sorted(by.items()):
    et=EntityType(et_name)
    feats=[semantic_v3_features(et,x['text'],x['start'],x['end'],x['pattern']) for x in items]
    names=sorted({k for f in feats for k in f})
    X=np.array([[f.get(n,0.0) for n in names] for f in feats],dtype=float)
    y=np.array([1 if x['accept'] else 0 for x in items],dtype=int)
    if len(set(y))<2: raise SystemExit(f'need pos/neg for {et_name}')
    model=LogisticRegression(C=3.0,solver='liblinear',class_weight='balanced',random_state=2603815,max_iter=500)
    model.fit(X,y)
    weights={n:round(float(w),7) for n,w in zip(names,model.coef_[0]) if abs(float(w))>=0.01}
    counts=Counter(y)
    out['classifiers'][et_name]={
      'intercept':round(float(model.intercept_[0]),7),'threshold':thresholds.get(et_name,0.65),
      'training_examples':{'positive':int(counts[1]),'negative':int(counts[0])},'weights':weights,
    }
model_path=root/'models'/'semantic_ner_v3.json'; model_path.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n',encoding='utf-8')
print(model_path); print('training',len(payload['examples']))
for k,v in out['classifiers'].items(): print(k,v['training_examples'],'threshold',v['threshold'])
