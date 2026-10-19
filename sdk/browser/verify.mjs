import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
const dir=await mkdtemp(join(tmpdir(),'keygate-sdk-'));
try {
 const result=spawnSync(process.execPath,['node_modules/typescript/bin/tsc','-p','tsconfig.json','--outDir',dir],{stdio:'inherit'});
 if(result.status!==0) throw new Error('SDK 编译失败');
 for(const file of ['index.js','index.d.ts']) if(!(await readFile(join(dir,file))).equals(await readFile(join('dist',file)))) throw new Error('SDK 产物与源文件不一致');
} finally {await rm(dir,{recursive:true,force:true});}
