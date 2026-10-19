"""Event-driven recovery experiment; supersedes the old Fig. 7(c) simulation."""
import csv
import json
from dataclasses import dataclass, asdict
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import t

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'results_recovery_corrected'

@dataclass(frozen=True)
class Config:
    population: int = 1000
    committee: int = 32
    epochs: int = 500
    seeds: int = 30
    attack_start: int = 250
    attacker_fraction: float = .15
    rational_fraction: float = .60
    historical_valid_events: int = 12
    tau: float = .4
    initial_deposit: float = 8.
    min_deposit: float = 8.
    rho: float = .7
    online: float = .95
    decay: float = .02
    reward_vti: float = .08
    penalty_vti: float = .35
    reward_money: float = 1.
    cost_money: float = .18
    threshold_fraction: float = 2/3
    conflicts_per_request: int = 2

def weights(x):
    return .25 + np.log1p(9*x)

def update(x, deposits, honest, detected, c):
    """Apply finalized attributable events only; all other identities retain state."""
    nx=x.copy(); nd=deposits.copy()
    nx[honest]=np.clip((1-c.decay)*x[honest]+c.reward_vti,0,1)
    nx[detected]=np.clip((1-c.decay)*x[detected]-c.penalty_vti,0,1)
    nd[detected]=0.  # full slash, no automatic top-up/re-admission
    return nx,nd

def run(seed,c):
    rng=np.random.default_rng(seed)
    ids=np.arange(c.population)
    shuffled=rng.permutation(ids)
    attackers=np.zeros(c.population,bool)
    attackers[shuffled[:round(c.attacker_fraction*c.population)]]=True
    rational=np.zeros(c.population,bool)
    offset=round(c.attacker_fraction*c.population)
    rational[shuffled[offset:offset+round(c.rational_fraction*c.population)]]=True
    # Explicit mature-history fixture: each identity has 12 verified historical
    # endorsement events. Registration itself still starts at zero.
    x=np.zeros(c.population)
    for _ in range(c.historical_valid_events):
        x=np.clip((1-c.decay)*x+c.reward_vti,0,1)
    deposits=np.full(c.population,c.initial_deposit)
    rows=[]; events=[]
    for epoch in range(c.epochs):
        eligible=(x>=c.tau)&(deposits>=c.min_deposit)
        pool=ids[eligible]
        if len(pool)<c.committee:
            raise RuntimeError('Insufficient committee; explicit abort required')
        # Assumed public-seed weighted election, without replacement.
        keys=np.log(np.maximum(rng.random(len(pool)),1e-15))/weights(x[pool])
        com=pool[np.argpartition(keys,-c.committee)[-c.committee:]]
        # Immutable epoch snapshot, before execution or audit.
        cw=weights(x[com]).copy(); threshold=c.threshold_fraction*cw.sum()
        conflict=np.zeros(c.committee,bool)
        conflict[rng.choice(c.committee,c.conflicts_per_request,replace=False)]=True
        active=(rng.random(c.committee)<c.online)&~conflict
        malicious=attackers[com]&(epoch>=c.attack_start)&active
        honest=active&~malicious
        # In this unbribed recovery experiment r-c > 0. H weakly improves
        # next-state VTI, L has no reward; rational members choose H when online.
        assert c.reward_money>c.cost_money
        detected=malicious&(rng.random(c.committee)<c.rho)
        allowed=~conflict
        allowed_weight=cw[allowed].sum()
        completed=float(allowed_weight>=threshold and cw[honest].sum()>=threshold)
        invalid_ready=float(allowed_weight>=threshold and cw[malicious].sum()>=threshold)
        row={'seed':seed,'epoch':epoch,'vti_attackers':x[attackers].mean(),
             'vti_nonattackers':x[~attackers].mean(),
             'attacker_committee_weight':cw[attackers[com]].sum()/cw.sum(),
             'active_malicious_weight':cw[malicious].sum()/cw.sum(),
             'eligible_attacker_fraction':eligible[attackers].mean(),
             'request_completed':completed,'invalid_threshold_reached':invalid_ready,
             'eligible_count':len(pool),'detected_members':int(detected.sum())}
        rows.append(row)
        hids=com[honest]; dids=com[detected]
        nx,nd=update(x,deposits,hids,dids,c)
        for pos,member in enumerate(com):
            action='M' if malicious[pos] else 'H' if honest[pos] else 'L'
            events.append({'seed':seed,'epoch':epoch,'member':int(member),
                'attacker':int(attackers[member]),'rational':int(rational[member]),
                'conflict':int(conflict[pos]),'action':action,'evidence':int(detected[pos]),
                'weight_snapshot':cw[pos],'threshold_snapshot':threshold,
                'vti_before':x[member],'vti_after':nx[member],
                'deposit_before':deposits[member],'deposit_after':nd[member]})
        unaffected=np.ones(c.population,bool); unaffected[hids]=False; unaffected[dids]=False
        assert np.array_equal(nx[unaffected],x[unaffected])
        x,deposits=nx,nd
    return rows,events

def write(path,rows):
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def interval(a,binary=False):
    n=len(a); mean=float(np.mean(a))
    if binary:  # Wilson interval remains informative even for 0/n or n/n.
        z=1.959963984540054; den=1+z*z/n
        center=(mean+z*z/(2*n))/den
        half=z*np.sqrt(mean*(1-mean)/n+z*z/(4*n*n))/den
        return mean,max(0,center-half),min(1,center+half)
    half=t.ppf(.975,n-1)*np.std(a,ddof=1)/np.sqrt(n)
    return mean,max(0,mean-half),min(1,mean+half)

def tests():
    c=Config();x=np.array([1.,.8,.6,.5]);d=np.full(4,8.)
    nx,nd=update(x,d,np.array([0]),np.array([1]),c)
    assert np.isclose(nx[1],.434)
    assert nd[1]==0 and np.array_equal(nx[2:],x[2:])
    assert np.array_equal(d,np.full(4,8.)) and x[1]==.8
    assert not ((nx[1]>=c.tau) and (nd[1]>=c.min_deposit))
    assert interval(np.zeros(30),True)[2]>0

def main():
    tests();c=Config();OUT.mkdir(exist_ok=True)
    (OUT/'parameters.json').write_text(json.dumps(asdict(c),indent=2),encoding='utf-8')
    allrows=[]
    # Event log is streamed per seed to keep memory bounded.
    with (OUT/'events.csv').open('w',newline='',encoding='utf-8') as f:
        writer=None
        for seed in range(c.seeds):
            rows,events=run(seed,c);allrows.extend(rows)
            if writer is None:
                writer=csv.DictWriter(f,fieldnames=list(events[0]));writer.writeheader()
            writer.writerows(events)
    write(OUT/'trajectories.csv',allrows)
    metrics=['vti_attackers','vti_nonattackers','attacker_committee_weight',
             'eligible_attacker_fraction','request_completed','invalid_threshold_reached']
    cube={m:np.array([r[m] for r in allrows]).reshape(c.seeds,c.epochs) for m in metrics}
    summary=[]
    for e in range(c.epochs):
        for m in metrics:
            mean,lo,hi=interval(cube[m][:,e],m in ['request_completed','invalid_threshold_reached'])
            summary.append(dict(epoch=e,metric=m,mean=mean,ci95_low=lo,ci95_high=hi,n=c.seeds))
    write(OUT/'summary.csv',summary)
    plt.rcParams.update({'font.family':'serif','font.serif':['Times New Roman','DejaVu Serif'],
        'font.size':8,'axes.labelsize':9,'legend.fontsize':7,'axes.linewidth':.7,'pdf.fonttype':42,'ps.fonttype':42})
    fig,axs=plt.subplots(1,2,figsize=(7.15,2.65),layout='constrained')
    def line(ax,m,label,color,marker):
        rows=[r for r in summary if r['metric']==m]
        es=np.arange(c.epochs);means=[r['mean'] for r in rows]
        ax.plot(es,means,label=label,color=color,lw=.9,marker=marker,markevery=25,ms=2.7)
        ax.fill_between(es,[r['ci95_low'] for r in rows],[r['ci95_high'] for r in rows],color=color,alpha=.13,lw=0)
    line(axs[0],'vti_nonattackers','Non-attacking identities','#4f81bd','o')
    line(axs[0],'vti_attackers','Attacker identities','#d95f5f','s')
    axs[0].axhline(c.tau,color='.45',ls=':',lw=.8,label='VTI eligibility threshold')
    axs[0].set(ylabel='Mean VTI',title='(a) Evidence-driven reputation')
    line(axs[1],'attacker_committee_weight','Attacker identity weight','#d95f5f','s')
    line(axs[1],'request_completed','Valid-request completion','#4f81bd','o')
    line(axs[1],'eligible_attacker_fraction','Eligible attacker fraction','#555555','^')
    axs[1].set(ylabel='Weight fraction / probability',title='(b) Exclusion and availability')
    for ax in axs:
        ax.axvspan(c.attack_start,c.epochs-1,color='#d95f5f',alpha=.035)
        ax.axvline(c.attack_start,color='.4',ls='--',lw=.7)
        ax.set(xlabel='Epoch',xlim=(0,c.epochs-1),ylim=(0,1.05))
        ax.legend(frameon=False,loc='center left');ax.tick_params(length=2.5)
    for ext in ['png','pdf','svg']:
        fig.savefig(OUT/f'fig_dynamic_recovery.{ext}',dpi=600,bbox_inches='tight')
    plt.close(fig)
    for e in [249,250,265,300,400,499]:
        print(e,{m:round(float(cube[m][:,e].mean()),4) for m in metrics})
    print('OUTPUT',OUT)

if __name__=='__main__':main()
