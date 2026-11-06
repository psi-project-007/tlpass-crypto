import { defineConfig } from 'vitest/config';               
import { playwright } from '@vitest/browser-playwright';    

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],                         
    coverage: {
      provider: 'v8',                                       
      include: ['src'],                                     
      thresholds: { lines: 90 },                            
    },
    browser: {
      provider: playwright(),                               
      headless: true,                                       
      instances: [{ browser: 'chromium' }],                 
    },                                                      
  },
});