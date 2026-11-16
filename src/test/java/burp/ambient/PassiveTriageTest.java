package burp.ambient;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PassiveTriageTest {

    private PassiveTriage.Sig sig(boolean idLike, boolean econ, boolean bodyParams,
                                  boolean jwt, boolean hasAuth, boolean graphql, boolean missingHeaders) {
        PassiveTriage.Sig s = new PassiveTriage.Sig();
        s.idLike = idLike; s.econ = econ; s.bodyParams = bodyParams;
        s.jwt = jwt; s.hasAuth = hasAuth; s.graphql = graphql; s.missingHeaders = missingHeaders;
        return s;
    }

    @Test
    void idLikeEndpointTaggedIdorAndScored() {
        PassiveTriage.Score sc = PassiveTriage.scoreOf(
                sig(true, false, false, false, true, false, false), false);
        assertTrue(sc.classes.contains(PassiveTriage.C_IDOR));
        assertEquals(30 + 15, sc.score, "idLike(+30) + hasAuth(+15)");
    }

    @Test
    void economicWriteEndpointFlaggedBusinessLogic() {
        PassiveTriage.Score sc = PassiveTriage.scoreOf(
                sig(false, true, true, false, false, false, false), false);
        assertTrue(sc.classes.contains(PassiveTriage.C_LOGIC));
        assertTrue(sc.classes.contains(PassiveTriage.C_MASSASSIGN));
        assertEquals(25 + 20, sc.score, "econ(+25) + bodyParams(+20)");
    }

    @Test
    void jwtBeatsPlainAuthAndDoesNotDoubleCount() {
        PassiveTriage.Score withJwt = PassiveTriage.scoreOf(
                sig(false, false, false, true, true, false, false), false);
        // jwt(+20) is taken instead of plain hasAuth(+15), not both
        assertEquals(20, withJwt.score);
        assertTrue(withJwt.classes.contains(PassiveTriage.C_AUTH));
    }

    @Test
    void boringEndpointScoresLow() {
        PassiveTriage.Score sc = PassiveTriage.scoreOf(
                sig(false, false, false, false, false, false, true), false);
        assertEquals(10, sc.score, "only missing-headers(+10)");
        assertTrue(sc.classes.contains(PassiveTriage.C_MISCONFIG));
    }

    @Test
    void scoreClampedTo100() {
        PassiveTriage.Score sc = PassiveTriage.scoreOf(
                sig(true, true, true, true, true, true, true), true);
        assertEquals(100, sc.score, "additive score is clamped at 100");
    }

    @Test
    void firstHostAddsReconNudge() {
        PassiveTriage.Score withFirst = PassiveTriage.scoreOf(
                sig(true, false, false, false, false, false, false), true);
        PassiveTriage.Score without = PassiveTriage.scoreOf(
                sig(true, false, false, false, false, false, false), false);
        assertEquals(without.score + 5, withFirst.score);
    }
}
