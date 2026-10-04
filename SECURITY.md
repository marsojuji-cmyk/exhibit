# Security Policy

## What this repository is

`exhibit` is a claim-tiered open-source-intelligence aggregation pipeline that attaches provenance to every output.

## Reporting a vulnerability

**Preferred: GitHub private vulnerability reporting.** Open the **Security** tab on this repository and
choose **Report a vulnerability**. That channel is private between you and the maintainer, requires no
email, and nothing is posted publicly. Private reporting is enabled on this repository.

If you cannot use that channel, open a **minimal public issue** stating only that you have a security
report and how to reach you. Please do **not** include exploit details, proof-of-concept code, or
affected-version specifics in a public issue.

## Scope

**In scope:** A path where aggregated content is presented without its provenance; a source whose tier is misrepresented; injection of content that survives into a published output; and any place a claim is asserted with higher confidence than the underlying source supports.

**Out of scope / stated plainly:** The accuracy of third-party sources is outside our control. This tool reports what sources said and how strongly it can vouch for them — it does not guarantee that a source is truthful.

## What to expect

| Stage | Commitment |
|---|---|
| Acknowledgement of your report | within 7 days |
| Initial assessment and severity call | within 14 days |
| Fix, or an agreed public disclosure | coordinated with you |

You will be credited in the fix or advisory unless you ask to remain anonymous.

## What this policy does NOT offer

There is **no bug bounty**, and no monetary reward is offered or implied. This is an independent
research project maintained by one person. What it can offer is a fast, honest response and public
credit.

## Related

- Our agent-systems threat posture and the method behind these reviews: see the `adversarial-seat`
  repository for the review method, and `hermes-refuse` for the fail-closed execution posture.
