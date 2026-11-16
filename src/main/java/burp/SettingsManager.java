package burp;

import org.json.*;
import java.util.*;

/**
 * Settings Manager - Load and save extension settings
 * 
 * @author Zahid Eroglu
 */
public class SettingsManager {
    
    private IBurpExtenderCallbacks callbacks;
    private Settings settings;
    
    private static final String SETTINGS_KEY = "ai_scanner_settings";
    
    public SettingsManager(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    /**
     * Load settings from Burp
     */
    public Settings loadSettings() {
        String savedSettings = callbacks.loadExtensionSetting(SETTINGS_KEY);
        
        if (savedSettings != null && !savedSettings.isEmpty()) {
            try {
                JSONObject json = new JSONObject(savedSettings);
                settings = Settings.fromJSON(json);
            } catch (Exception e) {
                settings = Settings.getDefaults();
            }
        } else {
            settings = Settings.getDefaults();
        }
        
        return settings;
    }
    
    /**
     * Save settings to Burp
     */
    public void saveSettings(Settings settings) {
        this.settings = settings;
        
        try {
            JSONObject json = settings.toJSON();
            callbacks.saveExtensionSetting(SETTINGS_KEY, json.toString());
        } catch (Exception e) {
            // Log error but don't fail
        }
    }
    
    /**
     * Get current settings
     */
    public Settings getSettings() {
        return settings;
    }
    
    /**
     * Update settings
     */
    public void updateSettings(Settings settings) {
        saveSettings(settings);
    }
}
