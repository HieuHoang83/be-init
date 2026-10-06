const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/haravan', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(async () => {
  console.log('Connected to MongoDB');
  
  const Shop = mongoose.model('Shop', new mongoose.Schema({
    orgId: Number,
    accessToken: String,
    accessTokenExpiresAt: Date,
    scopes: [String],
    createdAt: Date,
    updatedAt: Date,
  }));
  
  const orgId = 200001220496;
  const newToken = '9B55A0565284EBE7122D6908CB3D409652DAE745347937690E2EB8834375A0DC';
  const expiresIn = 473040000; // seconds from token response
  
  try {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + expiresIn * 1000);
    
    const result = await Shop.updateOne(
      { orgId },
      {
        $set: {
          accessToken: newToken,
          accessTokenExpiresAt: expiresAt,
        },
        $setOnInsert: { orgId },
      },
      { upsert: true }
    );
    
    console.log('Update result:', result);
    console.log(`Token updated for org ${orgId}`);
    console.log('Expires at:', expiresAt);
  } catch (error) {
    console.error('Error:', error);
  }
  
  mongoose.connection.close();
})
.catch(err => {
  console.error('MongoDB connection error:', err);
});
