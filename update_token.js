const { AccessTokenStore } = require('./src/api/access-token.store');
const { ConfigService } = require('./src/config.service');
require('dotenv').config();

async function updateToken() {
  // Initialize config
  const configService = new ConfigService();
  const config = configService.getConfig();
  
  const store = new AccessTokenStore(config, config.shopModel);
  
  const orgId = 200001220496; // Shop ID from user
  const newToken = '9B55A0565284EBE7122D6908CB3D409652DAE745347937690E2EB8834375A0DC';
  const expiresInSec = 473040000; // From the token response
  
  try {
    await store.persist(orgId, newToken, expiresInSec);
    console.log(`Token successfully updated for org ${orgId}`);
    console.log('Expires at:', new Date(Date.now() + expiresInSec * 1000));
  } catch (error) {
    console.error('Error updating token:', error);
  }
}

updateToken();
