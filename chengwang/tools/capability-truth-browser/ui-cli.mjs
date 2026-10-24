import { pathToFileURL } from 'node:url'
import { parseArguments } from './ui-contract.mjs'
import { runCapabilityTruth } from './ui-driver.mjs'
export async function main(args) {
  try { await runCapabilityTruth(parseArguments(args)); return 0 }
  catch { process.stderr.write('CAPABILITY_TRUTH=REJECTED raw_input_suppressed=true\n'); return 1 }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2))
