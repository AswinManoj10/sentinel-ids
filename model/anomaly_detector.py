"""Advanced Unsupervised Anomaly Detector: Isolation Forest + DBSCAN + LOF"""

import csv, math, random, os
from collections import deque

N_FEATURES = 10
BUFFER_MAX = 600
RETRAIN_FREQ = 30

FEATURE_NAMES = ["Hour Sin","Hour Cos","Username Len","Password Len",
                 "Pwd Entropy","Username Risk","SQL Flag","IP Variance","UA Length","Weekend"]

DATA_PATH = os.path.join(os.path.dirname(__file__), "../data/login_events.csv")

def _c(n):
    if n<=1: return 0.0
    return 2.0*(math.log(n-1)+0.5772156649)-2.0*(n-1)/n

def _dist(a,b):
    return math.sqrt(sum((x-y)**2 for x,y in zip(a,b)))

class _WelfordScaler:
    def __init__(self,n):
        self.n=0; self.mean=[0.0]*n; self.M2=[0.0]*n
    def update(self,x):
        self.n+=1
        for i,xi in enumerate(x):
            d=xi-self.mean[i]; self.mean[i]+=d/self.n; self.M2[i]+=d*(xi-self.mean[i])
    def scale(self,x):
        if self.n<2: return list(x)
        return [(xi-self.mean[i])/(math.sqrt(self.M2[i]/self.n)+1e-8) for i,xi in enumerate(x)]

class _IsoTree:
    __slots__=("size","feat","val","left","right")
    def __init__(self,X,d,md):
        self.size=len(X); self.feat=self.val=self.left=self.right=None
        if d>=md or len(X)<=1: return
        f=random.randint(0,len(X[0])-1)
        col=[r[f] for r in X]; mn,mx=min(col),max(col)
        if mn==mx: return
        v=random.uniform(mn,mx)
        L=[r for r in X if r[f]<v]; R=[r for r in X if r[f]>=v]
        if not L or not R: return
        self.feat,self.val=f,v
        nmd=math.ceil(math.log2(max(len(X),2)))
        self.left=_IsoTree(L,d+1,nmd); self.right=_IsoTree(R,d+1,nmd)
    def path(self,x,d=0):
        if self.feat is None: return d+_c(self.size)
        c=self.left if x[self.feat]<self.val else self.right
        return c.path(x,d+1) if c else d+1

class _IsoForest:
    def __init__(self,n_trees=80,max_samples=128,contamination=0.15):
        self.n_trees=n_trees; self.max_samples=max_samples
        self.contamination=contamination; self.trees=[]; self.threshold=0.5
        self._trained_n=0
    def fit(self,X):
        md=math.ceil(math.log2(max(self.max_samples,2)))
        self.trees=[_IsoTree(random.sample(X,min(self.max_samples,len(X))),0,md) for _ in range(self.n_trees)]
        self._trained_n=len(X)
        sc=sorted(self._raw(x) for x in X)
        self.threshold=sc[min(int(len(sc)*(1-self.contamination)),len(sc)-1)]
    def _raw(self,x):
        if not self.trees: return 0.5
        return 2.0**(-sum(t.path(x) for t in self.trees)/len(self.trees)/_c(self.max_samples))
    def score(self,x): return self._raw(x)
    def predict(self,x): return -1 if self._raw(x)>=self.threshold else 1

class _DBSCAN:
    def __init__(self,eps=1.5,min_pts=4): self.eps=eps; self.min_pts=min_pts
    def fit(self,X):
        n=len(X); labels=[-2]*n; C=0
        def nb(i): return [j for j in range(n) if i!=j and _dist(X[i],X[j])<=self.eps]
        for i in range(n):
            if labels[i]!=-2: continue
            nn=nb(i)
            if len(nn)<self.min_pts: labels[i]=-1; continue
            labels[i]=C
            seeds=set(nn)
            while seeds:
                s=seeds.pop()
                if labels[s]==-1: labels[s]=C
                if labels[s]!=-2: continue
                labels[s]=C
                sn=nb(s)
                if len(sn)>=self.min_pts: seeds.update(sn)
            C+=1
        return labels,C
    def silhouette(self,X,labels,maxs=100):
        ids=[i for i in range(len(X)) if labels[i]>=0]
        if len(ids)<4: return 0.0
        sample=random.sample(ids,min(maxs,len(ids))); scores=[]
        for i in sample:
            ci=labels[i]
            same=[j for j in ids if j!=i and labels[j]==ci]
            other_cls=set(labels[j] for j in ids if labels[j]!=ci)
            if not same or not other_cls: continue
            a=sum(_dist(X[i],X[j]) for j in same)/len(same)
            b=min(sum(_dist(X[i],X[j]) for j in ids if labels[j]==cl)/max(sum(1 for j in ids if labels[j]==cl),1) for cl in other_cls)
            if max(a,b)>0: scores.append((b-a)/max(a,b))
        return round(sum(scores)/len(scores),3) if scores else 0.0

class _LOF:
    def __init__(self,k=8,contamination=0.15): self.k=k; self.contamination=contamination; self._X=[]; self.threshold=999
    def fit(self,X):
        self._X=X[:]
        sc=sorted(self._lof_score(x,X) for x in X)
        self.threshold=sc[min(int(len(sc)*(1-self.contamination)),len(sc)-1)]
    def _knn(self,x,X): return sorted(range(len(X)),key=lambda i:_dist(x,X[i]))[:self.k]
    def _reach(self,x,y,X):
        nn=self._knn(y,X); k_d=_dist(y,X[nn[-1]]) if nn else 0
        return max(_dist(x,y),k_d)
    def _lrd(self,x,X):
        nn=self._knn(x,X)
        if not nn: return 1.0
        rd=sum(self._reach(x,X[j],X) for j in nn)/len(nn)
        return 1.0/max(rd,1e-8)
    def _lof_score(self,x,X):
        nn=self._knn(x,X)
        if not nn: return 1.0
        lrd_x=self._lrd(x,X)
        return sum(self._lrd(X[j],X) for j in nn)/(len(nn)*max(lrd_x,1e-8))
    def score(self,x):
        if not self._X: return 1.0
        return self._lof_score(x,self._X[:min(40,len(self._X))])
    def predict(self,x): return -1 if self.score(x)>=self.threshold else 1

class AnomalyDetector:
    def __init__(self):
        self._scaler=_WelfordScaler(N_FEATURES)
        self._forest=_IsoForest(n_trees=80,max_samples=128,contamination=0.15)
        self._dbscan=_DBSCAN(eps=1.5,min_pts=4)
        self._lof=_LOF(k=8,contamination=0.15)
        self._buffer=deque(maxlen=BUFFER_MAX); self._raw_buf=deque(maxlen=BUFFER_MAX)
        self._retrain_ctr=0
        self._db_labels=[]; self._db_nc=0; self._db_sil=0.0
        self._bootstrap()

    def _load_csv(self,with_labels=False):
        if not os.path.exists(DATA_PATH): return []
        rows=[]
        with open(DATA_PATH) as f:
            for row in csv.DictReader(f):
                try:
                    vec=[float(row[k]) for k in ["hour_sin","hour_cos","uname_len","pwd_len","pwd_entropy","uname_risk","sql_flag","ip_var","ua_len","weekend"]]
                    rows.append((vec,int(row["label"])) if with_labels else vec)
                except: pass
        return rows

    def _synth(self):
        rows=[]
        for _ in range(300):
            h=random.gauss(10,3)
            rows.append([math.sin(2*math.pi*h/24),math.cos(2*math.pi*h/24),
                         random.uniform(0.15,0.35),random.uniform(0.15,0.4),random.uniform(0.5,0.9),
                         0.0,0.0,random.uniform(0,0.3),random.uniform(0.3,0.6),0.0])
        for _ in range(60):
            h=random.choice([2,3,4,23,0,1])
            rows.append([math.sin(2*math.pi*h/24),math.cos(2*math.pi*h/24),
                         random.uniform(0.05,0.12),random.uniform(0.05,0.2),random.uniform(0.1,0.4),
                         random.choice([0.0,1.0]),random.choice([0.0,1.0]),random.uniform(0.5,1.0),
                         random.uniform(0,0.3),random.choice([0.0,1.0])])
        return rows

    def _bootstrap(self):
        rows=self._load_csv() or self._synth()
        for r in rows: self._scaler.update(r); self._buffer.append(self._scaler.scale(r)); self._raw_buf.append(r)
        buf=list(self._buffer)
        self._forest.fit(buf)
        self._lof.fit(random.sample(buf,min(80,len(buf))))
        self._refresh_db()

    def _refresh_db(self):
        buf=list(self._buffer)
        if len(buf)<8: return
        lbl,nc=self._dbscan.fit(buf)
        self._db_labels=lbl; self._db_nc=nc
        self._db_sil=self._dbscan.silhouette(buf,lbl)

    def predict(self,features):
        sc=self._scaler.scale(features)
        score=self._forest.score(sc)
        label="ANOMALY" if self._forest.predict(sc)==-1 else "NORMAL"
        return score,label

    def update(self,features):
        self._scaler.update(features)
        sc=self._scaler.scale(features)
        self._buffer.append(sc); self._raw_buf.append(features)
        self._retrain_ctr+=1
        if self._retrain_ctr>=RETRAIN_FREQ and len(self._buffer)>=60:
            buf=list(self._buffer)
            self._forest.fit(buf)
            self._lof.fit(random.sample(buf,min(80,len(buf))))
            self._refresh_db(); self._retrain_ctr=0

    def get_analytics(self):
        buf=list(self._buffer); n=len(buf)
        if n==0: return {}
        scores=[self._forest.score(x) for x in buf]
        anom=[s for s in scores if s>=self._forest.threshold]
        norm=[s for s in scores if s<self._forest.threshold]
        # LOF sample
        sample_idx=random.sample(range(n),min(50,n))
        lof_a=sum(1 for i in sample_idx if self._lof.score(buf[i])>=self._lof.threshold)
        lof_rate=round(lof_a/len(sample_idx)*100,1) if sample_idx else 0
        agree=sum(1 for i in sample_idx if (scores[i]>=self._forest.threshold)==(self._lof.score(buf[i])>=self._lof.threshold))
        agreement=round(agree/len(sample_idx)*100,1) if sample_idx else 0
        # Feature importance
        feat_vars=[]
        for fi in range(N_FEATURES):
            col=[x[fi] for x in buf]; m=sum(col)/len(col)
            feat_vars.append(sum((v-m)**2 for v in col)/len(col))
        tv=sum(feat_vars)+1e-8
        importance=[round(v/tv*100,1) for v in feat_vars]
        # Score histogram
        bins=[0]*10
        for s in scores: bins[min(int(s*10),9)]+=1
        # Evaluation from dataset
        gt=self._load_csv(with_labels=True)
        tp=fp=tn=fn=0
        if gt:
            sample_gt=random.sample(gt,min(500,len(gt)))
            for feat,lbl in sample_gt:
                sc2=self._scaler.scale(feat)
                pred=1 if self._forest.predict(sc2)==-1 else 0
                if pred==1 and lbl==1: tp+=1
                elif pred==1 and lbl==0: fp+=1
                elif pred==0 and lbl==1: fn+=1
                else: tn+=1
        prec=round(tp/max(tp+fp,1),3); rec=round(tp/max(tp+fn,1),3)
        f1=round(2*prec*rec/max(prec+rec,1e-8),3)
        acc=round((tp+tn)/max(tp+fp+tn+fn,1)*100,1)
        # DBSCAN stats
        nc=self._db_nc; noise=self._db_labels.count(-1) if self._db_labels else 0
        tl=len(self._db_labels)
        cls_sizes={}
        for l in self._db_labels:
            if l>=0: cls_sizes[str(l)]=cls_sizes.get(str(l),0)+1
        return {
            "total_samples":n,"anomaly_count":len(anom),"normal_count":len(norm),
            "anomaly_rate":round(len(anom)/n*100,1),"mean_score":round(sum(scores)/n,3),
            "threshold":round(self._forest.threshold,3),
            "if_n_trees":self._forest.n_trees,"if_contamination":self._forest.contamination,
            "if_trained_on":self._forest._trained_n,
            "lof_anomaly_rate":lof_rate,"model_agreement":agreement,
            "precision":prec,"recall":rec,"f1_score":f1,"accuracy":acc,
            "tp":tp,"tn":tn,"fp":fp,"fn":fn,
            "dbscan_clusters":nc,"dbscan_noise_ratio":round(noise/max(tl,1)*100,1),
            "dbscan_silhouette":self._db_sil,"dbscan_noise_count":noise,
            "dbscan_cluster_sizes":cls_sizes,
            "feature_importance":importance,"feature_names":FEATURE_NAMES,
            "score_histogram":bins,
            "score_mean_normal":round(sum(norm)/len(norm),3) if norm else 0,
            "score_mean_anomaly":round(sum(anom)/len(anom),3) if anom else 0,
        }

    def get_cluster_data(self):
        buf=list(self._buffer)
        if len(buf)<8: return {"points":[],"clusters":[],"n_clusters":0,"noise_count":0,"silhouette":0}
        labels=self._db_labels
        if len(labels)!=len(buf): self._refresh_db(); labels=self._db_labels
        idxs=random.sample(range(len(buf)),min(200,len(buf)))
        pts=[{"x":round(buf[i][0],3),"y":round(buf[i][1],3),"cluster":labels[i] if i<len(labels) else -1} for i in idxs]
        cids=sorted(set(p["cluster"] for p in pts if p["cluster"]>=0))
        clusters=[]
        for cid in cids:
            m=[p for p in pts if p["cluster"]==cid]
            clusters.append({"id":cid,"size":len(m),"centroid":[round(sum(p["x"] for p in m)/len(m),3),round(sum(p["y"] for p in m)/len(m),3)]})
        return {"points":pts,"clusters":clusters,"n_clusters":self._db_nc,
                "noise_count":sum(1 for p in pts if p["cluster"]==-1),"silhouette":self._db_sil}
