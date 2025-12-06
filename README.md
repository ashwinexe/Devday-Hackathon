# Devday-Hackathon

Apify actors project for the DevDay Hackathon - web scraping and automation using the Apify platform.

## Features

- Web scraping with [Crawlee](https://crawlee.dev/) and [Apify SDK](https://docs.apify.com/sdk/js/)
- Configurable start URLs and crawl limits
- Data extraction and storage
- Ready to deploy on the Apify platform

## Getting Started

### Prerequisites

- Node.js 18 or higher
- npm

### Installation

```bash
npm install
```

### Running Locally

```bash
npm start
```

### Configuration

The actor accepts the following input parameters:

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `startUrls` | Array | URLs to start crawling from | `[{ url: "https://apify.com" }]` |
| `maxRequestsPerCrawl` | Integer | Maximum number of pages to crawl | `100` |

### Deploying to Apify

1. Install the Apify CLI: `npm install -g apify-cli`
2. Login to Apify: `apify login`
3. Push the actor: `apify push`

## Project Structure

```
├── .actor/
│   ├── actor.json         # Actor configuration
│   ├── Dockerfile         # Docker build instructions
│   └── input_schema.json  # Input schema definition
├── src/
│   └── main.js            # Main actor code
├── package.json           # Node.js dependencies
└── README.md              # This file
```

## License

MIT License - see [LICENSE](LICENSE) for details.