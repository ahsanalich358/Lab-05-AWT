import bcrypt from 'bcryptjs';
import { randomUUID } from 'node:crypto';
export async function seedDemo(db) {
  const hashes=await Promise.all(Array.from({length:6},()=>bcrypt.hash('Lab05!DemoPass2026',12)));
  let index=0;
  db.transaction(()=>{
    for(const tenant of ['acme','globex']) {
      db.prepare('INSERT OR IGNORE INTO tenants VALUES(?,?)').run(tenant,tenant==='acme'?'Acme Corporation':'Globex Corporation');
      for(const [role,email,name] of [['SuperAdmin','admin','Workspace Admin'],['Manager','manager','Payroll Manager'],['Employee','employee','Team Member']]) {
        db.prepare('INSERT OR IGNORE INTO users(id,tenant_id,email,name,password_hash,role) VALUES(?,?,?,?,?,?)').run(randomUUID(),tenant,`${email}@${tenant}.test`,name,hashes[index++],role);
      }
      if(!db.prepare('SELECT id FROM payroll WHERE tenant_id=?').get(tenant)) db.prepare('INSERT INTO payroll(id,tenant_id) VALUES(?,?)').run(randomUUID(),tenant);
    }
  })();
}
