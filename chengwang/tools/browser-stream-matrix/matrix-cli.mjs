// Linux isolated CI entrypoint only. No execution when imported by contracts.
import { pathToFileURL } from 'node:url'
import { parseArguments } from './matrix-contract.mjs'
import { runMatrix } from './matrix-driver.mjs'
export async function main(args) {
  try { await runMatrix(parseArguments(args)); return 0 }
  catch { process.stderr.write('STREAM_MATRIX=REJECTED raw_input_suppressed=true\n'); return 1 }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2))
