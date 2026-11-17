package burp.businesslogic;

import burp.*;
import burp.api.ChainAttackDetector;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class WorkflowAnalyzerTest {

    @Mock
    private AiApiClient aiClient;
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

    private WorkflowAnalyzer workflowAnalyzer;

    @BeforeEach
    void setUp() throws Exception {
        // Log to file to ensure visibility - Use absolute path
        String basePath = "/Users/administrator/Downloads/Burp exteniton/ai-security-scanner/";
        stdout = new PrintWriter(new java.io.FileWriter(basePath + "debug_output.txt", true), true); // autoflush
        stderr = new PrintWriter(new java.io.FileWriter(basePath + "debug_error.txt", true), true);
        workflowAnalyzer = new WorkflowAnalyzer(aiClient, helpers, stdout, stderr);
    }

    @Test
    void testGenerateAttackChains() throws Exception {
        // Setup mock request
        when(helpers.analyzeRequest(requestResponse)).thenReturn(requestInfo);
        when(requestInfo.getUrl()).thenReturn(new URL("http://example.com/cart/add"));
        when(requestInfo.getMethod()).thenReturn("POST");

        // Mock request body
        when(requestResponse.getRequest()).thenReturn("POST /cart/add HTTP/1.1\r\n\r\n{}".getBytes());
        when(requestInfo.getBodyOffset()).thenReturn(24); // Approximation

        // Setup mock AI response
        JSONObject aiChoice = new JSONObject();
        JSONObject aiMessage = new JSONObject();

        // Mock a JSON response from AI describing a chain
        JSONObject chainJson = new JSONObject();
        chainJson.put("name", "Price Manipulation Chain");
        chainJson.put("description", "Modify price in cart");

        JSONArray steps = new JSONArray();
        JSONObject step1 = new JSONObject();
        step1.put("url", "http://example.com/cart/add");
        step1.put("method", "POST");
        step1.put("body", "{\"product_id\": 1, \"price\": 0.01}");
        steps.put(step1);

        chainJson.put("steps", steps);

        JSONArray chains = new JSONArray();
        chains.put(chainJson);

        aiMessage.put("content", chains.toString());
        aiChoice.put("message", aiMessage);

        JSONArray choices = new JSONArray();
        choices.put(aiChoice);

        JSONObject aiResponse = new JSONObject();
        aiResponse.put("choices", choices);

        when(aiClient.chatCompletion(any())).thenReturn(aiResponse);

        // Execute
        List<ChainAttackDetector.APIChain> result = workflowAnalyzer.generateAttackChains(requestResponse);

        // Verify
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("Price Manipulation Chain", result.get(0).name);
        assertEquals(1, result.get(0).steps.size());
        assertEquals("0.01", new JSONObject(result.get(0).steps.get(0).requestBody).get("price").toString());
    }
}
