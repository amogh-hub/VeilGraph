#!/usr/bin/env python3
"""Development-only reproducible trainer for VeilGraph Semantic NER v2.

Runtime inference does not import scikit-learn or NumPy. These dependencies are
required only when intentionally regenerating the committed local model.
"""
from pathlib import Path
from collections import defaultdict,Counter
import numpy as np
from sklearn.linear_model import LogisticRegression
root=Path(__file__).resolve().parents[1] / 'backend'
sys.path.insert(0,str(root))
from app.core.enums import EntityType
from app.detection.semantic_ner_v2 import semantic_v2_features
train_path=root/'training_data/semantic_ner_train_v2.json'
raw=train_path.read_bytes(); payload=json.loads(raw)
by=defaultdict(list)
for ex in payload['examples']: by[ex['entity_type']].append(ex)
out={'schema':'veilgraph.semantic-ner.linear.v2','version':'2.0.0','model_family':'local logistic-regression span classifier','runtime_network_required':False,'training_source':'VeilGraph independent fictional semantic-context corpus v2','training_corpus_sha256':hashlib.sha256(raw).hexdigest(),'classifiers':{}}
for et_name,items in sorted(by.items()):
    et=EntityType(et_name)
    feats=[semantic_v2_features(et,x['text'],x['start'],x['end'],x['pattern']) for x in items]
    names=sorted({k for f in feats for k in f})
    X=np.array([[f.get(n,0.0) for n in names] for f in feats],dtype=float)
    y=np.array([1 if x['accept'] else 0 for x in items],dtype=int)
    if len(set(y))<2:
        raise SystemExit(f'need pos/neg for {et_name}')
    model=LogisticRegression(C=4.0, solver='liblinear', class_weight='balanced', random_state=260381)
    model.fit(X,y)
    weights={n:round(float(w),6) for n,w in zip(names,model.coef_[0]) if abs(float(w))>=0.02}
    counts=Counter(y)
    out['classifiers'][et_name]={'intercept':round(float(model.intercept_[0]),6),'threshold':0.66 if et_name in {'PERSON_NAME','LOCALITY'} else 0.70,'training_examples':{'positive':counts[1],'negative':counts[0]},'weights':weights}
model_path=root/'models/semantic_ner_v2.json'; model_path.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(model_path)
print(json.dumps(out,indent=2)[:5000])