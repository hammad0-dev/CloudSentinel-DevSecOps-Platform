import { defineConfig } from '@playwright/test';
export default defineConfig({
 testDir:'./test',fullyParallel:false,workers:1,
 use:{baseURL:'http://127.0.0.1:5188',headless:true,channel:'chromium'},
 webServer:{command:'npm run dev -- --host 127.0.0.1 --port 5188 --strictPort',url:'http://127.0.0.1:5188',reuseExistingServer:false},
 reporter:'list',
});
