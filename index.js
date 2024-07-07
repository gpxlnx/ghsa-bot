const file = Bun.file('log.txt')
const log = await file.text()
const w = file.writer()
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))

function generate_embed_color(severity) {
  let color;

  switch (severity) {
    case 'low':
      color = 7909721;
      break;
    case 'medium':
      color = 16632664;
      break;
    case 'high':
      color = 16027660;
      break;
    case 'critical':
      color = 14495300;
      break;
    default:
      color = 15132648;
      break;
  }

  return color
}

function get_refs(data) {
  const refs = data.references

  return refs.map((ref, i) => {
    return `* ${ref}` +
      (i < refs.length - 1 ? '\n' : '')
  }).join('')
}

function get_vuln_pkgs(data) {
  const vulns = data.vulnerabilities

  return vulns.map((vuln, i) => {
    const pkg = vuln.package

    return `* \`${pkg.name}\` (${pkg.ecosystem}) version \`${vuln.vulnerable_version_range}\`` +
      (i < vulns.length - 1 ? '\n' : '')
  }).join('')
}

function get_severity_icon(severity) {
  let icon;

  switch (severity) {
    case 'low':
      icon = ':green_circle:'
      break;
    case 'medium':
      icon = ':yellow_circle:'
      break;
    case 'high':
      icon = ':orange_circle:'
      break;
    case 'critical':
      icon = ':red_circle:'
      break;
    default:
      icon = '-'
      severity = ''
      break;
  }

  return `${icon} ${severity.replace(/\b\w/g, char => char.toUpperCase())}`
}

function generate_payload(data) {
  return {
    "content": null,
    "embeds": [
      {
        "title": data.summary,
        "description": data.description,
        "color": generate_embed_color(data.severity),
        "fields": [
          {
            "name": "Vulnerable Packages",
            "value": get_vuln_pkgs(data),
            "inline": false
          },
          {
            "name": "Severity",
            "value": get_severity_icon(data.severity),
            "inline": true
          },
          {
            "name": "CVSS Score",
            "value": `${data.cvss.score || '-'}`,
            "inline": true
          },
          {
            "name": "References",
            "value": get_refs(data),
            "inline": false
          },
          {
            "name": "GHSA ID",
            "value": data.ghsa_id,
            "inline": true
          },
          {
            "name": "CVE ID",
            "value": data.cve_id,
            "inline": true
          }
        ],
        "author": {
          "name": data.source_code_location.replace('https://github.com/', ''),
          "url": data.source_code_location,
          "icon_url": data.source_code_location.replace(/\/[^\/]+$/, '.png')
        },
        "url": data.html_url,
        "footer": {
          "text": "dwisiswant0/ghsa-bot",
          "icon_url": "https://github.com/github.png"
        }
      }
    ],
    "attachments": []
  }
}

const req = await fetch("https://api.github.com/advisories", {
  "headers": {
    "accept": "application/vnd.github+json",
    "cache-control": "no-cache",
    "content-type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28"
  },
  "method": "GET"
})

const res = await req.json()

for (const data of res) {
  const id = data.ghsa_id

  if (log.includes(id)) {
    console.log(`${id} skipping...`)

    continue
  }

  const payload = generate_payload(data)
  const post = await fetch(Bun.env.DISCORD_WEBHOOK_URL, {
    method: 'POST',
    body: JSON.stringify(payload),
    headers: { 'Content-Type': 'application/json' },
  });

  if (post.ok) {
    console.log(`${id} OK`)

    w.write(`${id}\n`)
    await delay(5000)
  } else {
    console.log(post)
  }
}