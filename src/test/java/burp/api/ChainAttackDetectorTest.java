package burp.api;

import burp.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.PrintWriter;
import java.net.URL;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ChainAttackDetectorTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;
    @Mock
    private IExtensionHelpers helpers;
    @Mock
    private PrintWriter stdout;
    @Mock
    private PrintWriter stderr;
    @Mock
    private IHttpRequestResponse requestResponse;
    @Mock
    private IRequestInfo requestInfo;
    @Mock
    private IResponseInfo responseInfo;

    private ChainAttackDetector chainAttackDetector;

    @BeforeEach
    void setUp() {
        chainAttackDetector = new ChainAttackDetector(callbacks, helpers, stdout, stderr);
    }

    @Test
    void testExecuteChain() throws Exception {
        // Setup
        ChainAttackDetector.APIChain chain = new ChainAttackDetector.APIChain();
        chain.name = "Test Chain";

        // Step 1: Login (returns token)
        ChainAttackDetector.APIEndpoint step1 = new ChainAttackDetector.APIEndpoint("http://example.com/login", "POST");
        step1.path = "/login";
        chain.steps.add(step1);

        // Step 2: Use Token
        ChainAttackDetector.APIEndpoint step2 = new ChainAttackDetector.APIEndpoint("http://example.com/profile",
                "GET");
        step2.path = "/profile";
        step2.headers.put("Authorization", "Bearer {token}");
        chain.steps.add(step2);

        // Mock helpers
        when(helpers.buildHttpService(any(), anyInt(), anyBoolean())).thenReturn(mock(IHttpService.class));
        when(helpers.buildHttpMessage(any(), any())).thenReturn(new byte[0]);

        // Mock callbacks.makeHttpRequest for Step 1
        IHttpRequestResponse response1 = mock(IHttpRequestResponse.class);
        when(response1.getResponse()).thenReturn("HTTP/1.1 200 OK\r\n\r\n{\"token\": \"abc-123\"}".getBytes());

        // Mock callbacks.makeHttpRequest for Step 2
        IHttpRequestResponse response2 = mock(IHttpRequestResponse.class);
        when(response2.getResponse()).thenReturn("HTTP/1.1 200 OK\r\n\r\nSuccess".getBytes());

        // Configure callbacks to return different responses based on calls
        when(callbacks.makeHttpRequest(any(), any())).thenReturn(response1).thenReturn(response2);

        // Mock helpers.analyzeResponse
        IResponseInfo respInfo1 = mock(IResponseInfo.class);
        when(respInfo1.getStatusCode()).thenReturn((short) 200);
        when(respInfo1.getBodyOffset()).thenReturn(0); // For simplicity

        when(helpers.analyzeResponse(any())).thenReturn(respInfo1);

        // Execute
        ChainAttackDetector.ChainAttackResult result = chainAttackDetector.executeChain(chain);

        // Verify
        assertTrue(result.successful);
        assertEquals(2, result.executionLog.stream().filter(s -> s.startsWith("Step")).count());
    }
}
