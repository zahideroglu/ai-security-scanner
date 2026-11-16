package burp.authz;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.engine.DetectionStage;
import burp.engine.SharedRateLimiter;
import burp.engine.StageListener;

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Builds the {@link AccessModel} (ground-truth object ownership) from each identity's
 * proxy-history requests (path/param ids the identity successfully accessed, HTTP 200),
 * and optionally validates ownership with a silent active-discovery pass (re-sends the
 * owning GET requests; drops objects that no longer return 200). Scope is one host.
 *
 * @author Zahid Eroglu
 */
public class AccessModelBuilder {

    private static final Pattern NUM_SEG = Pattern.compile("^\\d{1,12}$");
    private static final Pattern UUID_SEG = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern HASH_SEG = Pattern.compile("^[0-9a-fA-F]{16,64}$"); // long hex id / hash
    private static final Pattern ID_VAL = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");
    private static final Set<String> ID_NAMES = new HashSet<>(Arrays.asList(
            "id", "userid", "user_id", "uid", "account", "accountid", "account_id", "orderid",
            "order_id", "docid", "fileid", "customerid", "invoice", "record", "number",
            // Faz 3: broaden object-id recognition (UUID/slug/ref + common resource ids)
            "uuid", "guid", "ref", "slug", "key", "cart", "cartid", "cart_id", "product", "productid",
            "product_id", "item", "itemid", "item_id", "ticket", "ticketid", "ticket_id", "project",
            "projectid", "project_id", "group", "groupid", "group_id", "message", "messageid", "message_id",
            // bare object names + banking/PII identifiers seen in request bodies (e.g. {"customerId":..},
            // {"customer":..}, {"accountNo":..}) — matched in addition to the *id / *_id suffix rule below.
            "customer", "customer_id", "customerno", "accountno", "account_no", "objectid", "object_id",
            "pid", "file", "doc", "refid", "reference", "contract", "contractid", "subscription",
            "subscriptionid", "transaction", "transactionid", "txn", "payment", "paymentid", "payee",
            "beneficiary", "card", "cardid", "cardno", "iban", "msisdn", "subscriber", "subscriberid"));

    /** A path segment that looks like an object identifier (numeric, UUID, or long hex/hash). */
    private static boolean looksLikeId(String seg) {
        return seg != null && (NUM_SEG.matcher(seg).matches()
                || UUID_SEG.matcher(seg).matches() || HASH_SEG.matcher(seg).matches());
    }

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    public AccessModelBuilder(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
    }

    public AccessModel build(List<SessionHarvester.DiscoveredRole> roles, boolean activeDiscovery,
                             SharedRateLimiter limiter, StageListener l) {
        AccessModel model = new AccessModel();

        // History pass: each identity owns the objects it accessed with HTTP 200.
        for (SessionHarvester.DiscoveredRole dr : roles) {
            String role = dr.session.roleName;
            for (IHttpRequestResponse h : dr.requests) extractObjects(model, role, h);
        }
        if (l != null) l.onStageProgress(DetectionStage.RECON,
                "Sahiplik haritası: " + model.totalObjects() + " nesne / " + model.roles.size() + " kimlik (history)");

        // Active discovery: silently re-send each owned GET to confirm it still returns 200 for the owner.
        if (activeDiscovery) {
            int validated = 0, dropped = 0;
            for (String role : model.roles) {
                List<AccessModel.OwnedObject> objs = model.ownedBy(role);
                java.util.Iterator<AccessModel.OwnedObject> it = objs.iterator();
                while (it.hasNext()) {
                    AccessModel.OwnedObject o = it.next();
                    if (!isGet(o.request)) continue; // never re-send mutating requests
                    if (limiter != null) limiter.acquire();
                    Integer sc = resend(o.request);
                    if (sc != null && sc == 200) {
                        validated++;
                    } else if (sc != null && (sc == 403 || sc == 404 || sc == 401)) {
                        it.remove(); // no longer owned/accessible -> keep the map honest
                        dropped++;
                    }
                }
            }
            if (l != null) l.onStageProgress(DetectionStage.RECON,
                    "Aktif keşif: " + validated + " sahiplik doğrulandı, " + dropped + " elendi");
        }
        return model;
    }

    private void extractObjects(AccessModel model, String role, IHttpRequestResponse h) {
        try {
            if (h.getResponse() == null) return;
            IResponseInfo resp = helpers.analyzeResponse(h.getResponse());
            if (resp.getStatusCode() != 200) return; // owner could actually access it
            IRequestInfo req = helpers.analyzeRequest(h);
            String[] segs = req.getUrl().getPath().split("/");
            for (int i = 0; i < segs.length; i++) {
                if (looksLikeId(segs[i])) {
                    String type = (i > 0 && !segs[i - 1].isEmpty()) ? segs[i - 1] : "object";
                    model.add(new AccessModel.OwnedObject(role, type, segs[i], "path", segs[i], h));
                }
            }
            for (IParameter p : req.getParameters()) {
                byte t = p.getType();
                if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY && t != IParameter.PARAM_JSON) continue;
                String n = p.getName().toLowerCase(Locale.ROOT); // ROOT: avoid tr_TR 'I'→'ı' breaking endsWith("id")/stem match
                // ID_NAMES / *id suffix + the "Hesap Aitlik Kontrolü" account-ownership fields
                // (AccountNumber, SenderAccountNumber, AccountSuffix, Iban, ReceiverIban, PersonId, …),
                // so an object owned via a body account-id is recorded for the ground-truth BOLA replay.
                if (ID_NAMES.contains(n) || n.endsWith("id") || n.endsWith("_id")
                        || OwnershipOracle.isAccountOwnershipParam(n)) {
                    String val = p.getValue();
                    if (val != null && ID_VAL.matcher(val).matches()) {
                        model.add(new AccessModel.OwnedObject(role, n, val, "param", p.getName(), h));
                    }
                }
            }
            // Nested / array JSON body ids (Burp's flat IParameter model misses these) — so an object owned
            // via {"account":{"id":..}} or [{"orderId":..}] is recorded for the ground-truth BOLA replay.
            if (req.getContentType() == IRequestInfo.CONTENT_TYPE_JSON && h.getRequest() != null) {
                int bo = req.getBodyOffset();
                byte[] rb = h.getRequest();
                if (bo < rb.length) {
                    String body = new String(rb, bo, rb.length - bo, java.nio.charset.StandardCharsets.UTF_8);
                    for (burp.scan.JsonIds.Hit hit : burp.scan.JsonIds.extract(body)) {
                        String jn = hit.name.toLowerCase(Locale.ROOT);
                        if ((ID_NAMES.contains(jn) || jn.endsWith("id") || jn.endsWith("_id")
                                || OwnershipOracle.isAccountOwnershipParam(jn))
                                && hit.value != null && ID_VAL.matcher(hit.value).matches()) {
                            model.add(new AccessModel.OwnedObject(role, jn, hit.value, "json", hit.name, h));
                        }
                    }
                }
            }
        } catch (Exception ignore) {
        }
    }

    private Integer resend(IHttpRequestResponse h) {
        try {
            IHttpRequestResponse rr = callbacks.makeHttpRequest(h.getHttpService(), h.getRequest());
            if (rr == null || rr.getResponse() == null) return null;
            return (int) helpers.analyzeResponse(rr.getResponse()).getStatusCode();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isGet(IHttpRequestResponse h) {
        try { return "GET".equalsIgnoreCase(helpers.analyzeRequest(h).getMethod()); }
        catch (Exception e) { return false; }
    }
}
