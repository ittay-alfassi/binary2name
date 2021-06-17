import angr

proj = angr.Project('dummy.out')
fobj = proj.loader.find_symbol('checkme')
state = proj.factory.call_state(fobj.rebased_addr)
simgr = proj.factory.simgr(state)

#what we know works - carol and abdallah's
simgr.run()
print(simgr.deadended[0].solver.constraints)
print(simgr.deadended[1].solver.constraints)

#what we hope works - ours
