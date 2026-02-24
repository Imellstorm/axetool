/**
 * WCAG 2.1 AA automated audit (axe-core based).
 *
 * AUDIT + COUNTS:
 * - Always full scan (as if limit=all).
 * - Counts ALWAYS include ALL findings (independent of limit).
 *
 * DETAILS OUTPUT:
 * - "limit" affects ONLY results/results_manual payload size:
 *   - default: 3 items per impact bucket
 *   - if limit === 'all': return all items
 *
 * IMPORTANT:
 * This is an AUTOMATED audit. WCAG compliance requires manual verification beyond automated checks.
 */

const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

app.use(cors());
app.use(express.json());

const allowedOrigin = 'https://axetool.devpoint.me';
const API_KEY =
	process.env.API_KEY || 'f7a2e5849c0d3b16e5f8d9c2a0b4e7f1d2c3b4a5';

const corsOptions = {
	origin: function (origin, callback) {
		if (origin === allowedOrigin || !origin) {
			callback(null, true);
		} else {
			callback(new Error('Not allowed by CORS'));
		}
	},
};

app.use(cors(corsOptions));
app.use(express.json());

const checkAccess = (req, res, next) => {
	const requestOrigin = req.get('Origin');
	if (requestOrigin === allowedOrigin) {
		return next();
	}

	const userApiKey = req.get('x-api-key');
	if (userApiKey) {
		try {
			const keyBuffer = Buffer.from(API_KEY, 'utf8');
			const userKeyBuffer = Buffer.from(userApiKey, 'utf8');

			if (
				keyBuffer.length === userKeyBuffer.length &&
				crypto.timingSafeEqual(keyBuffer, userKeyBuffer)
			) {
				return next();
			}
		} catch (e) {
		}
	}

	return res.status(403).json({
		error: 'Forbidden: Access denied. Invalid origin or missing/incorrect API key.',
	});
};

function initImpactCounters() {
	return {
		critical: 0,
		serious: 0,
		moderate: 0,
		minor: 0,
		null: 0,
	};
}

function normalizeImpact(impact) {
	if (impact === null || typeof impact === 'undefined') {
		return 'null';
	}
	return impact;
}

function initDetailsBuckets() {
	return {
		critical: [],
		serious: [],
		moderate: [],
		minor: [],
		null: [],
	};
}

function isAllLimit(limit) {
	return typeof limit === 'string' && limit.toLowerCase() === 'all';
}

function getDetailsBucketLimit(limit) {
	// limit controls ONLY payload details.
	return isAllLimit(limit) ? Infinity : 3;
}

app.get('/api/scan', (req, res) => {
	res.send('Server is working! ✅');
});

app.post('/api/scan', checkAccess, async (req, res) => {
	const {url, limit} = req.body;

	if (!url || !url.startsWith('http')) {
		return res.status(400).json({error: 'Invalid URL'});
	}

	const detailsLimit = getDetailsBucketLimit(limit);

	let browser;
	try {
		// Version from installed package (npm truth).
		let axePackageVersion = null;
		try {
			axePackageVersion = require('axe-core/package.json').version;
		} catch (e) {
			axePackageVersion = null;
		}

		browser = await puppeteer.launch({
			headless: 'new',
			args: ['--no-sandbox', '--disable-setuid-sandbox'],
		});

		const page = await browser.newPage();

		const viewport = {width: 1440, height: 900};
		await page.setViewport(viewport);

		await page.goto(url, {waitUntil: 'networkidle2', timeout: 60000});
		await new Promise((resolve) => setTimeout(resolve, 3000));

		const userAgent = await page.evaluate(() => {
			try {
				return navigator.userAgent || '';
			} catch (e) {
				return '';
			}
		});

		// Inject axe-core.
		const axeSource = fs.readFileSync(
			require.resolve('axe-core/axe.min.js'),
			'utf8'
		);
		await page.evaluate(axeSource);

		// Full audit run ALWAYS (independent of limit).
		const data = await page.evaluate(async () => {
			// @ts-ignore
			const axeVersion =
				typeof axe !== 'undefined' && axe.version ? axe.version : null;

			// @ts-ignore
			const results = await axe.run(document, {
				runOnly: {
					type: 'tag',
					values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'],
				},
				resultTypes: ['violations', 'incomplete', 'passes', 'inapplicable'],
			});

			return {axeVersion, results};
		});

		const axeRuntimeVersion = data && data.axeVersion ? data.axeVersion : null;
		const axeResults = data && data.results ? data.results : {};

		const violations = Array.isArray(axeResults.violations) ? axeResults.violations : [];
		const incomplete = Array.isArray(axeResults.incomplete) ? axeResults.incomplete : [];


		/**
		 * COUNTS (ALWAYS FULL):
		 * We count "errors" as NODE OCCURRENCES (each matched node is an issue occurrence).
		 * - summury: ONLY automatic failures (violations) by impact (node occurrences)
		 * - automatic_failures_by_impact: same as summury
		 * - manual_review_by_impact: incomplete by impact (node occurrences)
		 *
		 * Also return rule counts separately for transparency.
		 */
		const automaticFailuresByImpact = initImpactCounters();
		const manualReviewByImpact = initImpactCounters();

		let automaticRuleIssues = violations.length;
		let manualRuleIssues = incomplete.length;

		let automaticNodeIssuesTotal = 0;
		let manualNodeIssuesTotal = 0;

		/**
		 * DETAILS OUTPUT (LIMITED):
		 * - results: automatic failures only (violations)
		 * - results_manual: manual review only (incomplete)
		 * limited to <= detailsLimit items per impact bucket (unless limit=all).
		 */
		const detailsAutomatic = initDetailsBuckets();
		const detailsManual = initDetailsBuckets();

		function canPush(targetBuckets, impactKey) {
			return targetBuckets[impactKey].length < detailsLimit;
		}

		function pushNodeToBucket(targetBuckets, impactKey, item, sectionName, findingType, node) {
			if (!Array.isArray(targetBuckets[impactKey])) {
				return;
			}

			if (!canPush(targetBuckets, impactKey)) {
				return;
			}

			// Attach metadata for reporting/UI.
			node.ruleId = item.id;
			node.impact = item.impact;

			node.help = item.help;
			node.helpUrl = item.helpUrl;
			node.description = item.description;
			node.tags = item.tags;

			node.finding_section = sectionName; // "violations" | "incomplete"
			node.finding_type = findingType; // "automatic_failures_by_impact" | "manual_review_by_impact"

			targetBuckets[impactKey].push(node);
		}

		// Process violations (automatic).
		violations.forEach((item) => {
			const impactKey = normalizeImpact(item.impact);
			const nodes = Array.isArray(item.nodes) ? item.nodes : [];

			// COUNTS: count ALL nodes (full), independent of limit.
			nodes.forEach((node) => {
				if (typeof automaticFailuresByImpact[impactKey] === 'number') {
					automaticFailuresByImpact[impactKey]++;
				} else {
					automaticFailuresByImpact.null++;
				}
				automaticNodeIssuesTotal++;

				// DETAILS: limited by detailsLimit.
				pushNodeToBucket(
					detailsAutomatic,
					impactKey,
					item,
					'violations',
					'automatic_failures_by_impact',
					node
				);
			});
		});

		// Process incomplete (manual review).
		incomplete.forEach((item) => {
			const impactKey = normalizeImpact(item.impact);
			const nodes = Array.isArray(item.nodes) ? item.nodes : [];

			// COUNTS: count ALL nodes (full), independent of limit.
			nodes.forEach((node) => {
				if (typeof manualReviewByImpact[impactKey] === 'number') {
					manualReviewByImpact[impactKey]++;
				} else {
					manualReviewByImpact.null++;
				}
				manualNodeIssuesTotal++;

				// DETAILS: limited by detailsLimit.
				pushNodeToBucket(
					detailsManual,
					impactKey,
					item,
					'incomplete',
					'manual_review_by_impact',
					node
				);
			});
		});

		return res.json({
			meta: {
				url,
				timestamp_utc: new Date().toISOString(),
				user_agent: userAgent,
				viewport: viewport,

				axe_core_package_version: axePackageVersion,
				axe_core_runtime_version: axeRuntimeVersion,

				run_only_tags: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'],

				// limit affects ONLY details output
				details_limit_per_impact: detailsLimit === Infinity ? 'all' : detailsLimit,

				note:
					'Automated audit using axe-core. Counts always include all findings. Details may be limited unless limit="all". Full WCAG compliance requires manual verification beyond automated checks.',
			},

			/**
			 * LEGACY:
			 * summury must be ONLY automatic failures (violations) by impact,
			 * counted from FULL audit (independent of limit).
			 */
			summury: automaticFailuresByImpact,

			counts: {
				// Rule-level counts (how many rules fired).
				automatic_rule_issues: automaticRuleIssues,
				manual_review_rule_issues: manualRuleIssues,

				// Node-level counts (how many occurrences matched).
				automatic_node_issues_total: automaticNodeIssuesTotal,
				manual_review_node_issues_total: manualNodeIssuesTotal,

				// By impact (node-level occurrences), FULL audit.
				automatic_failures_by_impact: automaticFailuresByImpact,
				manual_review_by_impact: manualReviewByImpact,
			},

			/**
			 * Details split, LIMITED BY REQUESTED limit:
			 * - results: automatic failures only
			 * - results_manual: manual review only
			 */
			results: detailsAutomatic,
			results_manual: detailsManual,
		});
	} catch (error) {
		console.error('Puppeteer error:', error);
		return res.status(500).json({
			error: 'Failed to scan the page.',
			details: error.message,
		});
	} finally {
		if (browser) {
			await browser.close();
		}
	}
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});
