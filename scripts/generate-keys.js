// Utility script to generate secure keys

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Generate cryptographically strong random bytes
function generateRandomKey(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
}

// Main function
function main() {
    console.log('\n🔐 Generating Secure Keys for Your API\n');

    // Generate keys
    const accessTokenSecret = generateRandomKey();
    const refreshTokenSecret = generateRandomKey();
    const encryptionKey = generateRandomKey();

    console.log('Generated the following secure keys:');
    console.log('-----------------------------------');
    console.log(`JWT_ACCESS_SECRET=${accessTokenSecret}`);
    console.log(`JWT_REFRESH_SECRET=${refreshTokenSecret}`);
    console.log(`ENCRYPTION_KEY=${encryptionKey}`);
    console.log('-----------------------------------');

    // Check if .env file exists
    const envPath = path.join(__dirname, '..', '.env');

    if (fs.existsSync(envPath)) {
        console.log('\n⚠️ An .env file already exists. Do you want to update it with these keys? (y/n)');
        
        process.stdin.once('data', (data) => {
          const input = data.toString().trim().toLowerCase();
          
          if (input === 'y') {
            let envContent = fs.readFileSync(envPath, 'utf8');
            
            // Replace or add keys
            const updateEnvVar = (name, value) => {
              const regex = new RegExp(`${name}=.*`, 'g');
              if (envContent.match(regex)) {
                envContent = envContent.replace(regex, `${name}=${value}`);
              } else {
                envContent += `\n${name}=${value}`;
              }
            };
            
            updateEnvVar('JWT_ACCESS_SECRET', accessTokenSecret);
            updateEnvVar('JWT_REFRESH_SECRET', refreshTokenSecret);
            updateEnvVar('ENCRYPTION_KEY', encryptionKey);
            
            fs.writeFileSync(envPath, envContent);
            console.log('✅ .env file updated successfully!');
        }   else {
            console.log('❌ .env file not updated. You can manually add the keys if needed.');
        }
          
          process.exit(0);
        });
    }   else {
        console.log('\n⚠️ No .env file found. Creating a new one with these keys...');
        
        // Create a new .env file based on .env.example
        const exampleEnvPath = path.join(__dirname, '..', '.env.example');
        
        if (fs.existsSync(exampleEnvPath)) {
          let envContent = fs.readFileSync(exampleEnvPath, 'utf8');
          
          // Replace placeholder keys with generated ones
          envContent = envContent
            .replace(/JWT_ACCESS_SECRET=.*/, `JWT_ACCESS_SECRET=${accessTokenSecret}`)
            .replace(/JWT_REFRESH_SECRET=.*/, `JWT_REFRESH_SECRET=${refreshTokenSecret}`)
            .replace(/ENCRYPTION_KEY=.*/, `ENCRYPTION_KEY=${encryptionKey}`);
          
          fs.writeFileSync(envPath, envContent);
          console.log('✅ .env file created successfully!');
        } else {
          // Create a basic .env file with just the keys
          const basicEnv = `# Generated on ${new Date().toISOString()}
    PORT=3000
    NODE_ENV=development
    MONGODB_URI=mongodb://localhost:27017/secure-api
    JWT_ACCESS_SECRET=${accessTokenSecret}
    JWT_REFRESH_SECRET=${refreshTokenSecret}
    JWT_ACCESS_EXPIRES=15m
    JWT_REFRESH_EXPIRES=7d
    ENCRYPTION_KEY=${encryptionKey}
    `;
          
          fs.writeFileSync(envPath, basicEnv);
          console.log('✅ Basic .env file created successfully!');
        }
        
        process.exit(0);
    }
}
    
    // Run the script
    main();