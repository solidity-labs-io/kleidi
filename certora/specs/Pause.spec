import "ITimelock.spec";

invariant pauseDuration()
    to_mathint(pauseDuration()) >= to_mathint(oneDay()) &&
    to_mathint(pauseDuration()) <= to_mathint(oneMonth());

rule pausingCancelsAllInflightProposals(env e) {
    require getAllProposals().length > 0;

    pause(e);

    assert getAllProposals().length == 0, "proposals not cancelled post pause";
}

rule pausingRevokesGuardian(env e) {
    require pauseGuardian() != 0;
    require e.block.timestamp <= timestampMax() && e.block.timestamp > 0;

    pause(e);

    assert pauseGuardian() == 0, "pause guardian not revoked";
    assert to_mathint(pauseStartTime()) == to_mathint(e.block.timestamp), "pause start time not set";
    assert paused(e), "contract not paused";
    assert pauseUsed(), "contract not paused";
}
