"""Reproducible VTI endorsement-game simulation aligned with Eqs. (2), (4), (9)-(18).

This is a synthetic mechanism experiment, not an empirical blockchain trace.
Every output row records the seed and configured parameters.
"""
from __future__ import annotations

import csv, json, math
from dataclasses import asdict, dataclass
from pathlib import Path
import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
OUT = HERE / "results"
OUT.mkdir(parents=True, exist_ok=True)

@dataclass(frozen=True)
class P:
    population: int = 1000
    committee: int = 32
    epochs: int = 500
    seeds: int = 30
    tau: float = 0.40
    decay: float = 0.02
    delta_h: float = 0.08
    penalty_m: float = 0.35
    w_min: float = 0.25
    eta: float = 9.0
    threshold_fraction: float = 2/3
    discount: float = 0.95
    rollout_horizon: int = 50
    reward: float = 1.00
    cost: float = 0.18
    deposit: float = 8.0
    evidence_probability: float = 0.70
    genuine_fraction: float = 0.25
    rational_fraction: float = 0.60
    byzantine_fraction: float = 0.15
    shock_epoch: int = 250
    shock_duration: int = 15

CFG=P()

def weight(x, cfg=CFG): return cfg.w_min + np.log1p(cfg.eta*np.asarray(x))
def fh(x,cfg=CFG): return np.clip((1-cfg.decay)*np.asarray(x)+cfg.delta_h,0,1)
def fm(x,cfg=CFG): return np.clip((1-cfg.decay)*np.asarray(x)-cfg.penalty_m,0,1)

def continuation(x, mean_score, cfg=CFG):
    """Finite-horizon rollout of future honest committee rewards (Eq. 9)."""
    x=np.asarray(x,dtype=float); value=np.zeros_like(x); state=x.copy()
    denom=max(mean_score*cfg.population,1e-12)
    for k in range(cfg.rollout_horizon):
        eligible=state>=cfg.tau
        psel=np.minimum(1.0,cfg.committee*weight(state,cfg)/denom)*eligible
        value += (cfg.discount**k)*psel*(cfg.reward-cfg.cost)
        state=fh(state,cfg)
    return value

def utilities(x,rho,mean_score,bribe=0.0,cfg=CFG):
    """Return U(H), U(L), U(M;b), and beta_i from Eqs. (11)-(15)."""
    x=np.asarray(x,dtype=float)
    ph=continuation(fh(x,cfg),mean_score,cfg)
    pl=continuation(x,mean_score,cfg)
    pm=continuation(fm(x,cfg),mean_score,cfg)
    uh=cfg.reward-cfg.cost+cfg.discount*ph
    ul=cfg.discount*pl
    um=bribe-rho*cfg.deposit+cfg.discount*((1-rho)*pl+rho*pm)
    beta=np.maximum(uh-(um-bribe),0.0)
    return uh,ul,um,beta

def wswor(rng, ids, scores, k):
    if len(ids)<k: return np.array([],dtype=int)
    u=np.clip(rng.random(len(ids)),1e-15,1-1e-15)
    keys=np.log(u)/np.maximum(scores,1e-12)
    return ids[np.argpartition(keys,-k)[-k:]]

def cheapest_coalition(weights,costs,needed):
    """Exact binary MILP for Eq. (17); returns cost and solver status."""
    if needed<=0: return 0.0,"already_byzantine"
    if weights.sum()+1e-12<needed: return math.inf,"infeasible"
    c=np.asarray(costs,float); w=np.asarray(weights,float)
    res=milp(c,integrality=np.ones(len(c)),bounds=Bounds(0,1),
             constraints=LinearConstraint(w,needed,np.inf),options={"time_limit":10.0})
    if not res.success: return math.inf,f"milp_{res.status}"
    return float(res.fun),"optimal"

def simulate(seed,cfg=CFG):
    rng=np.random.default_rng(seed); n=cfg.population
    typ=np.full(n,1,dtype=np.int8) # rational
    typ[:round(n*cfg.genuine_fraction)]=0
    typ[-round(n*cfg.byzantine_fraction):]=2
    rng.shuffle(typ); x=np.zeros(n); rows=[]
    for e in range(cfg.epochs):
        eligible=np.flatnonzero(x>=cfg.tau); scores=weight(x[eligible],cfg) if len(eligible) else np.array([])
        com=wswor(rng,eligible,scores,cfg.committee) if len(eligible)>=cfg.committee else np.array([],dtype=int)
        mean_score=float(weight(x[x>=cfg.tau],cfg).mean()) if np.any(x>=cfg.tau) else cfg.w_min
        uh,ul,um,_=utilities(x,cfg.evidence_probability,mean_score,cfg=cfg)
        action=np.argmax(np.stack([uh,ul,um],axis=1),axis=1) # 0=H,1=L,2=M
        action[typ==0]=0
        attack=cfg.shock_epoch<=e<cfg.shock_epoch+cfg.shock_duration
        action[typ==2]=2 if attack else 0
        online=rng.random(n)<np.where(typ==0,.98,np.where(typ==1,.95,.98))
        action[~online]=1
        evidence=(action==2)&(rng.random(n)<cfg.evidence_probability)
        x[action==0]=fh(x[action==0],cfg)
        x[evidence]=fm(x[evidence],cfg)
        if len(com):
            cw=weight(x[com],cfg); mw=float(cw[action[com]==2].sum()/cw.sum())
            complete=float(cw[action[com]==0].sum()>=cfg.threshold_fraction*cw.sum())
        else: mw=np.nan; complete=0.0
        rows.append((seed,e,float(x[typ==0].mean()),float(x[typ==1].mean()),float(x[typ==2].mean()),mw,complete,
                     float(np.mean(action[typ==1]==0)),len(eligible)))
    return x,typ,rows

def write_csv(path,header,rows):
    with path.open("w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(header); w.writerows(rows)

def summary_ci(values):
    a=np.asarray(values,float); a=a[np.isfinite(a)]
    if len(a)==0:return (np.nan,np.nan,np.nan,np.nan)
    mean=float(a.mean()); ci=1.96*float(a.std(ddof=1))/math.sqrt(len(a)) if len(a)>1 else 0
    return mean,mean-ci,mean+ci,float(np.quantile(a,.95))

def main():
    with (OUT/"parameters.json").open("w",encoding="utf-8") as f: json.dump(asdict(CFG),f,indent=2)
    trajectories=[]; final=[]
    for seed in range(CFG.seeds):
        x,t,r=simulate(seed,CFG); trajectories.extend(r); final.append((x,t))
    write_csv(OUT/"vti_trajectories.csv",["seed","epoch","vti_genuine","vti_rational","vti_byzantine","malicious_committee_weight","request_completed","rational_honest_fraction","eligible_count"],trajectories)

    # Eq. (11)-(15) numerical validation surface.
    grid=np.linspace(0,1,101); mean_score=weight(.75,CFG)
    util=[]
    for rho in (.3,.5,.7,.9):
        uh,ul,um,beta=utilities(grid,rho,mean_score,cfg=CFG)
        util.extend((rho,float(xx),float(h),float(l),float(m),float(b)) for xx,h,l,m,b in zip(grid,uh,ul,um,beta))
    write_csv(OUT/"utility_surface.csv",["rho","vti","u_h","u_l","u_m_zero_bribe","min_bribe_beta"],util)

    # Committee snapshots: Eq. (17), economic margin, and realized budget response.
    budgets=np.linspace(0,160,9); rhos=np.linspace(.1,.9,9); econ=[]; deter=[]
    snap_rng=np.random.default_rng(9001)
    snapshots=[]
    for s,(x,t) in enumerate(final):
        eligible=np.flatnonzero(x>=CFG.tau); com=wswor(snap_rng,eligible,weight(x[eligible],CFG),CFG.committee)
        snapshots.append((s,x,t,com))
    for budget in budgets:
        successes=[]; nets=[]
        for seed,x,t,com in snapshots:
            cw=weight(x[com],CFG); threshold=CFG.threshold_fraction*cw.sum(); wb=cw[t[com]==2].sum()
            ridx=np.flatnonzero(t[com]==1); mean_score=weight(x[x>=CFG.tau],CFG).mean()
            beta=utilities(x[com][ridx],CFG.evidence_probability,mean_score,cfg=CFG)[3]
            cc,status=cheapest_coalition(cw[ridx],beta,threshold-wb)
            success=float(budget>=cc); net=(budget-cc) if success else 0.0
            successes.append(success); nets.append(net)
            econ.append((seed,budget,cc,status,success,net,float(wb/threshold)))
    for rho in rhos:
        vals=[]
        for seed,x,t,com in snapshots:
            cw=weight(x[com],CFG); threshold=CFG.threshold_fraction*cw.sum(); wb=cw[t[com]==2].sum(); ridx=np.flatnonzero(t[com]==1)
            mean_score=weight(x[x>=CFG.tau],CFG).mean(); beta=utilities(x[com][ridx],rho,mean_score,cfg=CFG)[3]
            cc,status=cheapest_coalition(cw[ridx],beta,threshold-wb); vals.append(cc)
            deter.append((seed,rho,cc,status,cc-40 if np.isfinite(cc) else np.inf))
    write_csv(OUT/"economic_boundary_raw.csv",["seed","attack_budget","min_corruption_cost","milp_status","attack_success","attacker_net","byzantine_weight_over_threshold"],econ)
    write_csv(OUT/"deterrence_raw.csv",["seed","rho","min_corruption_cost","milp_status","security_margin_at_value_40"],deter)

    # Availability sensitivity recomputes H/L choices from utilities.
    avail=[]
    for online in np.linspace(.65,1,8):
        for seed,x,t,com in snapshots:
            rng=np.random.default_rng(20000+seed+round(online*1000)); cw=weight(x[com],CFG); threshold=CFG.threshold_fraction*cw.sum()
            mean_score=weight(x[x>=CFG.tau],CFG).mean(); uh,ul,um,_=utilities(x[com],CFG.evidence_probability,mean_score,cfg=CFG)
            rational_h=(uh>=ul)&(uh>=um); willing=(t[com]==0)|((t[com]==1)&rational_h)
            active=rng.random(len(com))<online; completed=float(cw[willing&active].sum()>=threshold)
            avail.append((seed,online,float(rational_h[t[com]==1].mean()),completed))
    write_csv(OUT/"availability_raw.csv",["seed","online_probability","rational_honest_fraction","request_completed"],avail)

    summary=[]
    for metric, rows, key_index in [("attack_success",econ,4),("attacker_net",econ,5)]:
        for b in budgets:
            vals=[r[key_index] for r in rows if r[1]==b]; m,lo,hi,p95=summary_ci(vals)
            if metric=="attack_success": lo,hi=max(0,lo),min(1,hi)
            summary.append((metric,"attack_budget",b,m,lo,hi,p95,len(vals),0.0))
    for rho in rhos:
        rows=[r for r in deter if r[1]==rho]; vals=[r[2] for r in rows if np.isfinite(r[2])]
        m,lo,hi,p95=summary_ci(vals); inf=1-len(vals)/len(rows)
        summary.append(("min_corruption_cost","rho",rho,m,lo,hi,p95,len(vals),inf))
    for online in np.linspace(.65,1,8):
        for metric,idx in [("rational_honest_fraction",2),("request_completed",3)]:
            vals=[r[idx] for r in avail if r[1]==online]; m,lo,hi,p95=summary_ci(vals)
            lo,hi=max(0,lo),min(1,hi)
            summary.append((metric,"online_probability",online,m,lo,hi,p95,len(vals),0.0))
    write_csv(OUT/"vti_summary.csv",["metric","sweep","x","mean","ci95_low","ci95_high","p95","n","infeasible_rate"],summary)

    plot_all(grid,util,econ,deter,avail,trajectories)

def style():
    plt.rcParams.update({"font.family":"serif","font.serif":["Times New Roman","DejaVu Serif"],"font.size":8,
        "axes.labelsize":9,"legend.fontsize":7,"axes.linewidth":.75,"xtick.major.width":.7,"ytick.major.width":.7,
        "pdf.fonttype":42,"ps.fonttype":42})
def save(fig,name):
    for ext,kw in [("png",{"dpi":600}),("pdf",{}),("svg",{})]: fig.savefig(OUT/f"{name}.{ext}",bbox_inches="tight",**kw)
    plt.close(fig)
def plot_all(grid,util,econ,deter,avail,traj):
    style(); colors=["#4d4d4d","#d95f5f","#4f81bd","#63a66f"]
    u=np.array(util,float); fig,ax=plt.subplots(1,2,figsize=(7.1,2.15))
    q=u[np.isclose(u[:,0],.7)];
    for j,label in zip((2,3,4),("$U(H)$","$U(L)$","$U(M;0)$")): ax[0].plot(q[:,1],q[:,j],label=label,lw=1,marker=None)
    ax[0].axvline(CFG.tau,color=".5",ls="--",lw=.7); ax[0].set(xlabel="VTI $x$",ylabel="Discounted utility",title="(a) Strategy utilities ($\\rho=0.7$)"); ax[0].legend(frameon=False)
    for rho,c in zip((.3,.5,.7,.9),colors): q=u[np.isclose(u[:,0],rho)]; ax[1].plot(q[:,1],q[:,5],label=f"$\\rho={rho:.1f}$",color=c,lw=1)
    ax[1].set(xlabel="VTI $x$",ylabel="Minimum bribe $\\beta_i$",title="(b) Individual corruption price"); ax[1].legend(frameon=False,ncol=2)
    for a in ax:a.tick_params(direction="out",length=2.5);a.grid(False)
    fig.subplots_adjust(wspace=.32); save(fig,"fig_vti_utility_validation")

    fig,ax=plt.subplots(2,2,figsize=(7.1,4.6)); e=np.array([[r[1],r[4],r[5]] for r in econ],float)
    bs=np.unique(e[:,0]); means=[summary_ci(e[e[:,0]==b,1])[0] for b in bs]; cis=[summary_ci(e[e[:,0]==b,1]) for b in bs]
    l1,=ax[0,0].plot(bs,means,color=colors[1],marker="o",ms=3,lw=1,label="Attack success")
    ax[0,0].fill_between(bs,[max(0,x[1]) for x in cis],[min(1,x[2]) for x in cis],color=colors[1],alpha=.12,lw=0)
    ax00=ax[0,0].twinx(); net=[summary_ci(e[e[:,0]==b,2])[0] for b in bs]; l2,=ax00.plot(bs,net,color=colors[2],marker="s",ms=3,lw=1,label="Attacker net")
    ax[0,0].set(xlabel="Attack value / budget",ylabel="Attack success probability",title="(a) Economic boundary"); ax00.set_ylabel("Attacker net payoff")
    ax[0,0].legend([l1,l2],[l1.get_label(),l2.get_label()],frameon=False,loc="upper left")
    finite=[[r[1],r[2],r[4]] for r in deter if np.isfinite(r[2])]
    d=np.asarray(finite,float).reshape((-1,3)); rs=np.unique(d[:,0]) if len(d) else np.array([]); dc=[summary_ci(d[d[:,0]==r,1]) for r in rs]; cc=[x[0] for x in dc]
    ax[0,1].plot(rs,cc,color=colors[2],marker="o",ms=3,lw=1); ax[0,1].axhline(40,color=colors[1],ls="--",lw=.8,label="$V_{attack}=40$")
    if len(dc): ax[0,1].fill_between(rs,[x[1] for x in dc],[x[2] for x in dc],color=colors[2],alpha=.12,lw=0)
    ax[0,1].set(xlabel="Evidence probability $\\rho$",ylabel="Minimum corruption cost",title="(b) Source of deterrence"); ax[0,1].legend(frameon=False)
    tr=np.array(traj,float); epochs=np.unique(tr[:,1]); mw=[]; bv=[]
    for ep in epochs:
        z=tr[tr[:,1]==ep]; finite_mw=z[np.isfinite(z[:,5]),5]
        mw.append(float(finite_mw.mean()) if len(finite_mw) else np.nan); bv.append(np.mean(z[:,4]))
    ax[1,0].plot(epochs,bv,color=colors[1],lw=1,label="Byzantine VTI"); ax[1,0].plot(epochs,mw,color=colors[0],lw=1,label="Malicious committee weight")
    ax[1,0].axvspan(CFG.shock_epoch,CFG.shock_epoch+CFG.shock_duration,color=colors[1],alpha=.12,label="Latent attack")
    ax[1,0].set(xlabel="Epoch",ylabel="Mean / weight fraction",title="(c) Dynamic recovery"); ax[1,0].legend(frameon=False)
    av=np.array(avail,float); os=np.unique(av[:,1]); hs=[summary_ci(av[av[:,1]==o,2]) for o in os]; cs=[summary_ci(av[av[:,1]==o,3]) for o in os]; hp=[x[0] for x in hs]; cp=[x[0] for x in cs]
    ax[1,1].plot(os,hp,color=colors[3],marker="o",ms=3,lw=1,label="Rational honest choice"); ax[1,1].plot(os,cp,color=colors[2],marker="s",ms=3,lw=1,label="Request completion")
    ax[1,1].fill_between(os,[max(0,x[1]) for x in cs],[min(1,x[2]) for x in cs],color=colors[2],alpha=.12,lw=0)
    ax[1,1].set(xlabel="Online probability",ylabel="Probability",title="(d) Availability"); ax[1,1].legend(frameon=False)
    for a in ax.flat:a.tick_params(direction="out",length=2.5);a.grid(False)
    fig.subplots_adjust(wspace=.52,hspace=.42); save(fig,"fig_vti_game_main")

if __name__=="__main__": main()
