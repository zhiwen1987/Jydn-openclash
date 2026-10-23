import {pathToFileURL} from 'node:url'
import {parseArguments} from './handoff-negative-contract.mjs'
import {runHandoffNegativeUI} from './handoff-negative-driver.mjs'
export async function main(args){try{await runHandoffNegativeUI(parseArguments(args));return 0}catch{process.stderr.write('HANDOFF_NEGATIVE_UI=REJECTED raw_input_suppressed=true\n');return 1}}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)process.exitCode=await main(process.argv.slice(2))
