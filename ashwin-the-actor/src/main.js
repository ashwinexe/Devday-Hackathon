/**
 * Hackathon Cheating Detector Actor
 * 
 * Analyzes hackathon project submissions on Devfolio & Devpost for potential cheating:
 * - Pre-hackathon GitHub commits
 * - Reused projects from past hackathons
 * - Video timestamps before hackathon dates
 * - Team member submission history analysis
 */

import { Actor } from 'apify';
import { PlaywrightCrawler, Dataset, createPlaywrightRouter } from 'crawlee';

// Initialize the Actor
await Actor.init();

// ============================================================================
// CONFIGURATION & INPUT
// ============================================================================

const input = await Actor.getInput() ?? {};
const {
    mode = 'single_project',
    projectUrl,
    hackathonUrl,
    hackathonStartDate,
    hackathonEndDate,
    githubToken,
    maxProjectsToScan = 50,
    deepAnalysis = true,
    checkGitHubCommits = true,
    checkTeamHistory = true,
    checkVideoTimestamps = true,
    suspicionThreshold = 30,
    maxRequestsPerCrawl = 500,
} = input;

// Validate input
if (mode === 'single_project' && !projectUrl) {
    throw new Error('Project URL is required for single project analysis mode');
}
if (mode === 'hackathon_scan' && !hackathonUrl) {
    throw new Error('Hackathon URL is required for hackathon scan mode');
}

const hackathonStart = hackathonStartDate ? new Date(hackathonStartDate) : null;
const hackathonEnd = hackathonEndDate ? new Date(hackathonEndDate) : null;

console.log(`🔍 Hackathon Cheating Detector Starting...`);
console.log(`📋 Mode: ${mode}`);
console.log(`📅 Hackathon Period: ${hackathonStartDate || 'N/A'} to ${hackathonEndDate || 'N/A'}`);

// Proxy configuration
const proxyConfiguration = await Actor.createProxyConfiguration();

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Detect platform from URL
 */
function detectPlatform(url) {
    if (url.includes('devfolio.co')) return 'devfolio';
    if (url.includes('devpost.com')) return 'devpost';
    return 'unknown';
}

/**
 * Extract GitHub repos from text/links
 */
function extractGitHubUrls(text, links = []) {
    const githubRegex = /https?:\/\/github\.com\/[\w-]+\/[\w.-]+/gi;
    const matches = text.match(githubRegex) || [];
    const linkMatches = links.filter(l => l.includes('github.com'));
    return [...new Set([...matches, ...linkMatches])];
}

/**
 * Extract video URLs (YouTube, Loom, Vimeo)
 */
function extractVideoUrls(text, links = []) {
    const videoRegex = /https?:\/\/(www\.)?(youtube\.com\/watch\?v=|youtu\.be\/|loom\.com\/share\/|vimeo\.com\/)[\w-]+/gi;
    const matches = text.match(videoRegex) || [];
    const linkMatches = links.filter(l => 
        l.includes('youtube.com') || 
        l.includes('youtu.be') || 
        l.includes('loom.com') ||
        l.includes('vimeo.com')
    );
    return [...new Set([...matches, ...linkMatches])];
}

/**
 * Fetch GitHub commit data using GitHub API
 */
async function analyzeGitHubRepo(repoUrl, log) {
    const analysis = {
        repoUrl,
        analyzed: false,
        totalCommits: 0,
        commitsBeforeHackathon: 0,
        commitsDuringHackathon: 0,
        commitsAfterHackathon: 0,
        firstCommitDate: null,
        lastCommitDate: null,
        suspiciousPatterns: [],
        contributors: [],
        error: null,
    };

    try {
        // Extract owner/repo from URL
        const match = repoUrl.match(/github\.com\/([\w-]+)\/([\w.-]+)/);
        if (!match) {
            analysis.error = 'Invalid GitHub URL format';
            return analysis;
        }

        const [, owner, repo] = match;
        const cleanRepo = repo.replace(/\.git$/, '');
        
        const headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Hackathon-Cheating-Detector',
        };
        
        if (githubToken) {
            headers['Authorization'] = `token ${githubToken}`;
        }

        // Fetch commits (up to 100)
        const commitsResponse = await fetch(
            `https://api.github.com/repos/${owner}/${cleanRepo}/commits?per_page=100`,
            { headers }
        );

        if (!commitsResponse.ok) {
            if (commitsResponse.status === 404) {
                analysis.error = 'Repository not found or private';
            } else if (commitsResponse.status === 403) {
                analysis.error = 'GitHub API rate limit exceeded. Consider adding a GitHub token.';
            } else {
                analysis.error = `GitHub API error: ${commitsResponse.status}`;
            }
            return analysis;
        }

        const commits = await commitsResponse.json();
        analysis.analyzed = true;
        analysis.totalCommits = commits.length;

        // Analyze commit timestamps
        const commitDates = commits.map(c => ({
            date: new Date(c.commit.author.date),
            sha: c.sha.substring(0, 7),
            message: c.commit.message.split('\n')[0].substring(0, 50),
            author: c.commit.author.name,
        }));

        if (commitDates.length > 0) {
            analysis.firstCommitDate = commitDates[commitDates.length - 1].date.toISOString();
            analysis.lastCommitDate = commitDates[0].date.toISOString();
        }

        // Categorize commits by date
        for (const commit of commitDates) {
            if (hackathonStart && commit.date < hackathonStart) {
                analysis.commitsBeforeHackathon++;
            } else if (hackathonEnd && commit.date > hackathonEnd) {
                analysis.commitsAfterHackathon++;
            } else {
                analysis.commitsDuringHackathon++;
            }
        }

        // Get unique contributors
        analysis.contributors = [...new Set(commitDates.map(c => c.author))];

        // Detect suspicious patterns
        if (hackathonStart && analysis.commitsBeforeHackathon > 0) {
            const preHackathonPercent = (analysis.commitsBeforeHackathon / analysis.totalCommits) * 100;
            if (preHackathonPercent > 50) {
                analysis.suspiciousPatterns.push({
                    type: 'PRE_HACKATHON_MAJORITY',
                    severity: 'HIGH',
                    description: `${preHackathonPercent.toFixed(0)}% of commits were made before the hackathon started`,
                });
            } else if (analysis.commitsBeforeHackathon > 5) {
                analysis.suspiciousPatterns.push({
                    type: 'PRE_HACKATHON_COMMITS',
                    severity: 'MEDIUM',
                    description: `${analysis.commitsBeforeHackathon} commits found before hackathon start date`,
                });
            }
        }

        // Check for bulk commits (many commits in short time - possibly force pushed)
        const commitTimes = commitDates.map(c => c.date.getTime()).sort();
        let bulkCommitCount = 0;
        for (let i = 1; i < commitTimes.length; i++) {
            const timeDiff = commitTimes[i] - commitTimes[i - 1];
            if (timeDiff < 60000) { // Less than 1 minute apart
                bulkCommitCount++;
            }
        }
        if (bulkCommitCount > 10) {
            analysis.suspiciousPatterns.push({
                type: 'BULK_COMMITS',
                severity: 'MEDIUM',
                description: `${bulkCommitCount} commits made within 1 minute of each other (possible history manipulation)`,
            });
        }

        // Check for old repository
        if (analysis.firstCommitDate) {
            const firstCommit = new Date(analysis.firstCommitDate);
            const monthsOld = hackathonStart 
                ? (hackathonStart - firstCommit) / (1000 * 60 * 60 * 24 * 30)
                : 0;
            
            if (monthsOld > 3) {
                analysis.suspiciousPatterns.push({
                    type: 'OLD_REPOSITORY',
                    severity: 'HIGH',
                    description: `Repository is ${Math.floor(monthsOld)} months older than hackathon start`,
                });
            }
        }

        log.info(`GitHub Analysis: ${repoUrl} - ${analysis.totalCommits} commits, ${analysis.suspiciousPatterns.length} suspicious patterns`);

    } catch (error) {
        analysis.error = error.message;
        log.warning(`GitHub analysis failed for ${repoUrl}: ${error.message}`);
    }

    return analysis;
}

/**
 * Analyze video upload date
 */
async function analyzeVideoUrl(videoUrl, log) {
    const analysis = {
        videoUrl,
        platform: null,
        uploadDate: null,
        suspicious: false,
        suspicionReason: null,
        error: null,
    };

    try {
        if (videoUrl.includes('youtube.com') || videoUrl.includes('youtu.be')) {
            analysis.platform = 'youtube';
            // Extract video ID
            let videoId;
            if (videoUrl.includes('youtu.be/')) {
                videoId = videoUrl.split('youtu.be/')[1]?.split(/[?&]/)[0];
            } else {
                videoId = new URL(videoUrl).searchParams.get('v');
            }
            
            if (videoId) {
                // Use YouTube oEmbed to get basic info (no API key needed)
                const oembedUrl = `https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=${videoId}&format=json`;
                const response = await fetch(oembedUrl);
                if (response.ok) {
                    const data = await response.json();
                    analysis.title = data.title;
                    analysis.author = data.author_name;
                    // Note: oEmbed doesn't provide upload date, would need YouTube Data API for that
                    log.info(`YouTube video found: "${data.title}" by ${data.author_name}`);
                }
            }
        } else if (videoUrl.includes('loom.com')) {
            analysis.platform = 'loom';
            // Loom doesn't have a public API, but we note it exists
            log.info(`Loom video found: ${videoUrl}`);
        } else if (videoUrl.includes('vimeo.com')) {
            analysis.platform = 'vimeo';
            const videoId = videoUrl.split('vimeo.com/')[1]?.split(/[?/]/)[0];
            if (videoId) {
                const oembedUrl = `https://vimeo.com/api/oembed.json?url=https://vimeo.com/${videoId}`;
                const response = await fetch(oembedUrl);
                if (response.ok) {
                    const data = await response.json();
                    analysis.title = data.title;
                    analysis.author = data.author_name;
                    if (data.upload_date) {
                        analysis.uploadDate = data.upload_date;
                        const uploadDateObj = new Date(data.upload_date);
                        if (hackathonStart && uploadDateObj < hackathonStart) {
                            analysis.suspicious = true;
                            analysis.suspicionReason = `Video uploaded on ${data.upload_date}, before hackathon start`;
                        }
                    }
                    log.info(`Vimeo video found: "${data.title}"`);
                }
            }
        }
    } catch (error) {
        analysis.error = error.message;
        log.warning(`Video analysis failed for ${videoUrl}: ${error.message}`);
    }

    return analysis;
}

/**
 * Calculate suspicion score based on analysis results
 */
function calculateSuspicionScore(projectData) {
    let score = 0;
    const flags = [];

    // GitHub analysis scoring
    if (projectData.githubAnalysis?.length > 0) {
        for (const repo of projectData.githubAnalysis) {
            if (repo.analyzed) {
                for (const pattern of (repo.suspiciousPatterns || [])) {
                    if (pattern.severity === 'HIGH') {
                        score += 25;
                        flags.push(`🔴 ${pattern.description}`);
                    } else if (pattern.severity === 'MEDIUM') {
                        score += 15;
                        flags.push(`🟡 ${pattern.description}`);
                    } else {
                        score += 5;
                        flags.push(`🟢 ${pattern.description}`);
                    }
                }
            }
            if (repo.error === 'Repository not found or private') {
                score += 10;
                flags.push('🟡 GitHub repo is private or deleted');
            }
        }
    }

    // Team history scoring
    if (projectData.historyAnalysis?.similarProjects?.length > 0) {
        const similar = projectData.historyAnalysis.similarProjects;
        for (const proj of similar) {
            if (proj.similarity > 0.8) {
                score += 30;
                flags.push(`🔴 Very similar project found: "${proj.name}" (${(proj.similarity * 100).toFixed(0)}% match)`);
            } else if (proj.similarity > 0.5) {
                score += 15;
                flags.push(`🟡 Similar project found: "${proj.name}" (${(proj.similarity * 100).toFixed(0)}% match)`);
            }
        }
    }

    // Video analysis scoring
    if (projectData.videoAnalysis?.length > 0) {
        for (const video of projectData.videoAnalysis) {
            if (video.suspicious) {
                score += 20;
                flags.push(`🔴 ${video.suspicionReason}`);
            }
        }
    }

    // No GitHub link at all (suspicious for tech projects)
    if (!projectData.githubUrls?.length) {
        score += 5;
        flags.push('🟡 No GitHub repository linked');
    }

    // Cap score at 100
    score = Math.min(score, 100);

    // Determine verdict
    let verdict;
    if (score >= 70) {
        verdict = '🚨 HIGH RISK';
    } else if (score >= 40) {
        verdict = '⚠️ SUSPICIOUS';
    } else if (score >= 20) {
        verdict = '🔍 NEEDS REVIEW';
    } else {
        verdict = '✅ LIKELY CLEAN';
    }

    return { score, flags, verdict };
}

/**
 * Generate one-line summary for quick review
 */
function generateSummary(projectData, flags) {
    if (flags.length === 0) {
        return 'No suspicious activity detected.';
    }
    
    // Get the most severe flag
    const highFlags = flags.filter(f => f.includes('🔴'));
    const medFlags = flags.filter(f => f.includes('🟡'));
    
    if (highFlags.length > 0) {
        return highFlags[0].replace(/^🔴\s*/, '');
    } else if (medFlags.length > 0) {
        return medFlags[0].replace(/^🟡\s*/, '');
    }
    return flags[0].replace(/^🟢\s*/, '');
}

// ============================================================================
// CRAWLERS
// ============================================================================

// Store for collected project data
const projectsData = new Map();

// Create router for different page types
const router = createPlaywrightRouter();

// -------------------------
// DEVFOLIO HANDLERS
// -------------------------

// Handle Devfolio hackathon page (list of projects)
router.addHandler('DEVFOLIO_HACKATHON', async ({ page, request, log, crawler }) => {
    log.info(`Scraping Devfolio hackathon: ${request.url}`);
    
    await page.waitForLoadState('networkidle');
    
    // Scroll to load more projects (Devfolio uses infinite scroll)
    let previousHeight = 0;
    let projectLinks = [];
    
    for (let i = 0; i < 10; i++) {
        await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
        await page.waitForTimeout(2000);
        
        const currentHeight = await page.evaluate(() => document.body.scrollHeight);
        
        // Get all project links
        projectLinks = await page.$$eval('a[href*="/projects/"]', links => 
            links.map(l => l.href).filter(href => href.includes('/projects/'))
        );
        
        log.info(`Found ${projectLinks.length} projects so far...`);
        
        if (currentHeight === previousHeight || 
            (maxProjectsToScan > 0 && projectLinks.length >= maxProjectsToScan)) {
            break;
        }
        previousHeight = currentHeight;
    }

    // Deduplicate and limit
    projectLinks = [...new Set(projectLinks)];
    if (maxProjectsToScan > 0) {
        projectLinks = projectLinks.slice(0, maxProjectsToScan);
    }

    log.info(`Queuing ${projectLinks.length} Devfolio projects for analysis`);

    // Queue each project for analysis
    for (const url of projectLinks) {
        await crawler.addRequests([{
            url,
            label: 'DEVFOLIO_PROJECT',
            userData: { hackathonUrl: request.url }
        }]);
    }
});

// Handle Devfolio individual project page
router.addHandler('DEVFOLIO_PROJECT', async ({ page, request, log, crawler }) => {
    log.info(`Analyzing Devfolio project: ${request.url}`);
    
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000); // Wait for dynamic content
    
    const projectData = {
        projectUrl: request.url,
        platform: 'devfolio',
        projectName: null,
        description: null,
        teamMembers: [],
        githubUrls: [],
        videoUrls: [],
        allLinks: [],
        hackathonUrl: request.userData.hackathonUrl || null,
    };

    try {
        // Get project name
        projectData.projectName = await page.$eval('h1', el => el.textContent?.trim()).catch(() => null);
        
        // Get description
        projectData.description = await page.$eval('[class*="description"], [class*="Description"], .project-description', 
            el => el.textContent?.trim()
        ).catch(() => '');
        
        // If no description found, try getting all paragraph text
        if (!projectData.description) {
            projectData.description = await page.$$eval('p', els => 
                els.map(el => el.textContent?.trim()).filter(t => t && t.length > 50).join(' ')
            ).catch(() => '');
        }

        // Get all links on the page
        projectData.allLinks = await page.$$eval('a[href]', links => 
            links.map(l => l.href).filter(h => h && !h.startsWith('javascript'))
        );

        // Extract GitHub URLs
        projectData.githubUrls = extractGitHubUrls(projectData.description || '', projectData.allLinks);
        
        // Extract video URLs
        projectData.videoUrls = extractVideoUrls(projectData.description || '', projectData.allLinks);

        // Get team members
        const teamSection = await page.$$eval('[class*="team"] a[href*="/"], [class*="member"] a, [class*="builder"] a', 
            els => els.map(el => ({
                name: el.textContent?.trim(),
                profileUrl: el.href
            })).filter(m => m.name && m.profileUrl)
        ).catch(() => []);
        
        projectData.teamMembers = teamSection;

        log.info(`Project: ${projectData.projectName}, GitHub repos: ${projectData.githubUrls.length}, Team: ${projectData.teamMembers.length}`);

    } catch (error) {
        log.warning(`Error extracting Devfolio project data: ${error.message}`);
    }

    // Store for later analysis
    projectsData.set(request.url, projectData);

    // Queue team member profile analysis if deep analysis is enabled
    if (deepAnalysis && checkTeamHistory && projectData.teamMembers.length > 0) {
        for (const member of projectData.teamMembers) {
            if (member.profileUrl && member.profileUrl.includes('devfolio.co')) {
                await crawler.addRequests([{
                    url: member.profileUrl,
                    label: 'DEVFOLIO_PROFILE',
                    userData: { 
                        projectUrl: request.url,
                        memberName: member.name 
                    }
                }]);
            }
        }
    }
});

// Handle Devfolio user profile (to check past projects)
router.addHandler('DEVFOLIO_PROFILE', async ({ page, request, log }) => {
    const { projectUrl, memberName } = request.userData;
    log.info(`Checking Devfolio profile for ${memberName}: ${request.url}`);
    
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    try {
        // Get past projects
        const pastProjects = await page.$$eval('a[href*="/projects/"]', links =>
            links.map(l => ({
                name: l.textContent?.trim(),
                url: l.href
            })).filter(p => p.name && p.url)
        ).catch(() => []);

        // Update project data with team member history
        const projectData = projectsData.get(projectUrl);
        if (projectData) {
            if (!projectData.teamMemberHistory) {
                projectData.teamMemberHistory = [];
            }
            projectData.teamMemberHistory.push({
                memberName,
                profileUrl: request.url,
                pastProjects: pastProjects.filter(p => p.url !== projectUrl) // Exclude current project
            });
            projectsData.set(projectUrl, projectData);
        }

        log.info(`${memberName} has ${pastProjects.length} projects on Devfolio`);
    } catch (error) {
        log.warning(`Error checking profile ${request.url}: ${error.message}`);
    }
});

// -------------------------
// DEVPOST HANDLERS
// -------------------------

// Handle Devpost hackathon page
router.addHandler('DEVPOST_HACKATHON', async ({ page, request, log, crawler }) => {
    log.info(`Scraping Devpost hackathon: ${request.url}`);
    
    await page.waitForLoadState('networkidle');
    
    let projectLinks = [];
    let pageNum = 1;
    
    // Devpost uses pagination
    while (true) {
        await page.waitForTimeout(2000);
        
        // Get project links from current page
        const links = await page.$$eval('a.link-to-software', els => 
            els.map(el => el.href)
        ).catch(() => []);
        
        projectLinks.push(...links);
        log.info(`Page ${pageNum}: Found ${links.length} projects (total: ${projectLinks.length})`);
        
        if (maxProjectsToScan > 0 && projectLinks.length >= maxProjectsToScan) {
            break;
        }
        
        // Check for next page
        const nextButton = await page.$('a.next_page:not(.disabled)');
        if (!nextButton) break;
        
        await nextButton.click();
        await page.waitForLoadState('networkidle');
        pageNum++;
        
        if (pageNum > 20) break; // Safety limit
    }

    // Deduplicate and limit
    projectLinks = [...new Set(projectLinks)];
    if (maxProjectsToScan > 0) {
        projectLinks = projectLinks.slice(0, maxProjectsToScan);
    }

    log.info(`Queuing ${projectLinks.length} Devpost projects for analysis`);

    for (const url of projectLinks) {
        await crawler.addRequests([{
            url,
            label: 'DEVPOST_PROJECT',
            userData: { hackathonUrl: request.url }
        }]);
    }
});

// Handle Devpost individual project page
router.addHandler('DEVPOST_PROJECT', async ({ page, request, log, crawler }) => {
    log.info(`Analyzing Devpost project: ${request.url}`);
    
    await page.waitForLoadState('networkidle');
    
    const projectData = {
        projectUrl: request.url,
        platform: 'devpost',
        projectName: null,
        description: null,
        teamMembers: [],
        githubUrls: [],
        videoUrls: [],
        allLinks: [],
        hackathonUrl: request.userData.hackathonUrl || null,
    };

    try {
        // Get project name
        projectData.projectName = await page.$eval('#app-title', el => el.textContent?.trim()).catch(() => null);
        
        // Get description
        projectData.description = await page.$eval('#app-details-left', el => el.textContent?.trim()).catch(() => '');

        // Get all links
        projectData.allLinks = await page.$$eval('a[href]', links => 
            links.map(l => l.href).filter(h => h && !h.startsWith('javascript'))
        );

        // Get specific link buttons (GitHub, etc.)
        const buttonLinks = await page.$$eval('.app-links a', els => els.map(el => el.href)).catch(() => []);
        projectData.allLinks.push(...buttonLinks);

        // Extract GitHub URLs
        projectData.githubUrls = extractGitHubUrls(projectData.description || '', projectData.allLinks);
        
        // Extract video URLs
        projectData.videoUrls = extractVideoUrls(projectData.description || '', projectData.allLinks);
        
        // Also check for embedded video
        const embedVideo = await page.$eval('#video-section iframe', el => el.src).catch(() => null);
        if (embedVideo) {
            projectData.videoUrls.push(embedVideo);
        }

        // Get team members
        projectData.teamMembers = await page.$$eval('#app-team .user-profile-link', els => 
            els.map(el => ({
                name: el.textContent?.trim(),
                profileUrl: el.href
            })).filter(m => m.name)
        ).catch(() => []);

        log.info(`Project: ${projectData.projectName}, GitHub repos: ${projectData.githubUrls.length}, Team: ${projectData.teamMembers.length}`);

    } catch (error) {
        log.warning(`Error extracting Devpost project data: ${error.message}`);
    }

    projectsData.set(request.url, projectData);

    // Queue team member profile analysis
    if (deepAnalysis && checkTeamHistory && projectData.teamMembers.length > 0) {
        for (const member of projectData.teamMembers) {
            if (member.profileUrl && member.profileUrl.includes('devpost.com')) {
                await crawler.addRequests([{
                    url: member.profileUrl,
                    label: 'DEVPOST_PROFILE',
                    userData: { 
                        projectUrl: request.url,
                        memberName: member.name 
                    }
                }]);
            }
        }
    }
});

// Handle Devpost user profile
router.addHandler('DEVPOST_PROFILE', async ({ page, request, log }) => {
    const { projectUrl, memberName } = request.userData;
    log.info(`Checking Devpost profile for ${memberName}: ${request.url}`);
    
    await page.waitForLoadState('networkidle');

    try {
        // Get past projects from profile
        const pastProjects = await page.$$eval('.software-entry a.link-to-software', links =>
            links.map(l => ({
                name: l.querySelector('.software-entry-name')?.textContent?.trim() || l.textContent?.trim(),
                url: l.href
            })).filter(p => p.name && p.url)
        ).catch(() => []);

        const projectData = projectsData.get(projectUrl);
        if (projectData) {
            if (!projectData.teamMemberHistory) {
                projectData.teamMemberHistory = [];
            }
            projectData.teamMemberHistory.push({
                memberName,
                profileUrl: request.url,
                pastProjects: pastProjects.filter(p => p.url !== projectUrl)
            });
            projectsData.set(projectUrl, projectData);
        }

        log.info(`${memberName} has ${pastProjects.length} projects on Devpost`);
    } catch (error) {
        log.warning(`Error checking profile ${request.url}: ${error.message}`);
    }
});

// ============================================================================
// MAIN CRAWLER SETUP
// ============================================================================

const crawler = new PlaywrightCrawler({
    proxyConfiguration,
    maxRequestsPerCrawl,
    maxConcurrency: 3, // Be gentle with servers
    navigationTimeoutSecs: 60,
    requestHandlerTimeoutSecs: 120,
    requestHandler: router,
    
    preNavigationHooks: [
        async ({ page }) => {
            // Set a realistic viewport
            await page.setViewportSize({ width: 1280, height: 800 });
        },
    ],
    
    failedRequestHandler: async ({ request, log }, error) => {
        log.warning(`Request failed: ${request.url} - ${error.message}`);
    },
});

// ============================================================================
// START CRAWLING
// ============================================================================

const startRequests = [];

if (mode === 'single_project') {
    const platform = detectPlatform(projectUrl);
    startRequests.push({
        url: projectUrl,
        label: platform === 'devfolio' ? 'DEVFOLIO_PROJECT' : 'DEVPOST_PROJECT',
    });
} else if (mode === 'hackathon_scan') {
    const platform = detectPlatform(hackathonUrl);
    startRequests.push({
        url: hackathonUrl,
        label: platform === 'devfolio' ? 'DEVFOLIO_HACKATHON' : 'DEVPOST_HACKATHON',
    });
}

console.log(`🚀 Starting crawler with ${startRequests.length} initial request(s)`);
await crawler.run(startRequests);

// ============================================================================
// POST-CRAWL ANALYSIS
// ============================================================================

console.log(`\n📊 Performing deep analysis on ${projectsData.size} projects...\n`);

const results = [];

for (const [url, projectData] of projectsData) {
    console.log(`Analyzing: ${projectData.projectName || url}`);
    
    // GitHub commit analysis
    if (checkGitHubCommits && projectData.githubUrls.length > 0) {
        projectData.githubAnalysis = [];
        for (const repoUrl of projectData.githubUrls) {
            const analysis = await analyzeGitHubRepo(repoUrl, { 
                info: console.log, 
                warning: console.warn 
            });
            projectData.githubAnalysis.push(analysis);
        }
    }

    // Video analysis
    if (checkVideoTimestamps && projectData.videoUrls.length > 0) {
        projectData.videoAnalysis = [];
        for (const videoUrl of projectData.videoUrls) {
            const analysis = await analyzeVideoUrl(videoUrl, {
                info: console.log,
                warning: console.warn
            });
            projectData.videoAnalysis.push(analysis);
        }
    }

    // Team history analysis - check for similar projects
    if (checkTeamHistory && projectData.teamMemberHistory?.length > 0) {
        projectData.historyAnalysis = {
            membersChecked: projectData.teamMemberHistory.length,
            totalPastProjects: 0,
            similarProjects: [],
        };

        for (const member of projectData.teamMemberHistory) {
            projectData.historyAnalysis.totalPastProjects += member.pastProjects.length;
            
            // Simple similarity check based on project name
            for (const pastProject of member.pastProjects) {
                const currentName = (projectData.projectName || '').toLowerCase();
                const pastName = (pastProject.name || '').toLowerCase();
                
                // Calculate simple word overlap
                const currentWords = new Set(currentName.split(/\s+/).filter(w => w.length > 2));
                const pastWords = new Set(pastName.split(/\s+/).filter(w => w.length > 2));
                
                if (currentWords.size > 0 && pastWords.size > 0) {
                    const intersection = [...currentWords].filter(w => pastWords.has(w));
                    const similarity = intersection.length / Math.max(currentWords.size, pastWords.size);
                    
                    if (similarity > 0.3) {
                        projectData.historyAnalysis.similarProjects.push({
                            name: pastProject.name,
                            url: pastProject.url,
                            memberName: member.memberName,
                            similarity,
                        });
                    }
                }
            }
        }
    }

    // Calculate final score
    const { score, flags, verdict } = calculateSuspicionScore(projectData);
    const summary = generateSummary(projectData, flags);

    const result = {
        projectName: projectData.projectName || 'Unknown Project',
        projectUrl: url,
        platform: projectData.platform,
        suspicionScore: score,
        verdict,
        flags,
        summary,
        teamMembers: projectData.teamMembers.map(m => m.name),
        githubAnalysis: projectData.githubAnalysis || null,
        historyAnalysis: projectData.historyAnalysis || null,
        videoAnalysis: projectData.videoAnalysis || null,
        analyzedAt: new Date().toISOString(),
    };

    results.push(result);

    // Save to dataset
    await Dataset.pushData(result);

    console.log(`  → Score: ${score}/100 | Verdict: ${verdict}`);
    if (flags.length > 0) {
        console.log(`  → Flags: ${flags.join(', ')}`);
    }
    console.log('');
}

// ============================================================================
// FINAL SUMMARY
// ============================================================================

const flaggedCount = results.filter(r => r.suspicionScore >= suspicionThreshold).length;
const highRiskCount = results.filter(r => r.suspicionScore >= 70).length;
const suspiciousCount = results.filter(r => r.suspicionScore >= 40 && r.suspicionScore < 70).length;

console.log('═'.repeat(60));
console.log('📊 ANALYSIS COMPLETE');
console.log('═'.repeat(60));
console.log(`Total projects analyzed: ${results.length}`);
console.log(`🚨 High Risk: ${highRiskCount}`);
console.log(`⚠️  Suspicious: ${suspiciousCount}`);
console.log(`🚩 Flagged (score ≥ ${suspicionThreshold}): ${flaggedCount}`);
console.log(`✅ Likely Clean: ${results.length - flaggedCount}`);
console.log('═'.repeat(60));

if (highRiskCount > 0) {
    console.log('\n🚨 HIGH RISK PROJECTS:');
    results
        .filter(r => r.suspicionScore >= 70)
        .sort((a, b) => b.suspicionScore - a.suspicionScore)
        .forEach(r => {
            console.log(`  • ${r.projectName} (Score: ${r.suspicionScore})`);
            console.log(`    ${r.projectUrl}`);
            console.log(`    ${r.summary}`);
        });
}

// Gracefully exit
await Actor.exit();
