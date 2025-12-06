import { Actor } from 'apify';
import { CheerioCrawler } from 'crawlee';

await Actor.init();

// Get input from the Apify platform
const input = await Actor.getInput() ?? {};
const {
    startUrls = [{ url: 'https://apify.com' }],
    maxRequestsPerCrawl = 100,
} = input;

// Create a request queue and add the start URLs to it
const requestQueue = await Actor.openRequestQueue();
for (const startUrl of startUrls) {
    await requestQueue.addRequest(startUrl);
}

// Create a CheerioCrawler that will use the request queue
const crawler = new CheerioCrawler({
    requestQueue,
    maxRequestsPerCrawl,
    async requestHandler({ request, $, enqueueLinks, log }) {
        log.info(`Processing ${request.url}...`);

        // Extract page title
        const title = $('title').text();

        // Store the result
        await Actor.pushData({
            url: request.url,
            title,
        });

        // Find and enqueue links on the current page
        await enqueueLinks();
    },
    failedRequestHandler({ request, log }) {
        log.error(`Request ${request.url} failed.`);
    },
});

// Run the crawler
await crawler.run();

await Actor.exit();
