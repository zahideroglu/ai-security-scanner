package burp.spec;

import burp.IHttpRequestResponse;
import burp.IHttpService;

/**
 * Lightweight {@link IHttpRequestResponse} holding request bytes + a target service,
 * with no response yet. Used for endpoints synthesised from an OpenAPI/Swagger spec
 * so they can flow through the same replay/scan paths as captured traffic.
 *
 * @author Zahid Eroglu
 */
public class SyntheticHttpRequestResponse implements IHttpRequestResponse {

    private byte[] request;
    private byte[] response;
    private IHttpService service;
    private String comment = "";
    private String highlight;

    public SyntheticHttpRequestResponse(byte[] request, IHttpService service) {
        this.request = request;
        this.service = service;
    }

    public byte[] getRequest() { return request; }
    public void setRequest(byte[] message) { this.request = message; }

    public byte[] getResponse() { return response; }
    public void setResponse(byte[] message) { this.response = message; }

    public String getComment() { return comment; }
    public void setComment(String comment) { this.comment = comment; }

    public String getHighlight() { return highlight; }
    public void setHighlight(String color) { this.highlight = color; }

    public IHttpService getHttpService() { return service; }
    public void setHttpService(IHttpService httpService) { this.service = httpService; }
}
