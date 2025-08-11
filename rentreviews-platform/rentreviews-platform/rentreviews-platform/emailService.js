const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendVerificationEmail = async (email, firstName, token) => {
  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
  
  const msg = {
    to: email,
    from: {
      email: process.env.FROM_EMAIL,
      name: 'LandlordReviews'
    },
    subject: 'Verify your email address',
    html: `
      <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif;">
        <h2 style="color: #333;">Welcome to LandlordReviews, ${firstName}!</h2>
        
        <p>Thank you for joining our platform. To get started, please verify your email address by clicking the button below:</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationUrl}" 
             style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Verify Email Address
          </a>
        </div>
        
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
        
        <p style="margin-top: 30px; color: #666; font-size: 14px;">
          This verification link will expire in 24 hours. If you didn't create an account with us, you can safely ignore this email.
        </p>
        
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #999; font-size: 12px;">
          © 2025 LandlordReviews. Building trust in the rental market.
        </p>
      </div>
    `
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ Verification email sent to ${email}`);
  } catch (error) {
    console.error('❌ Email sending failed:', error);
    throw new Error('Failed to send verification email');
  }
};

const sendPasswordResetEmail = async (email, firstName, token) => {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
  
  const msg = {
    to: email,
    from: {
      email: process.env.FROM_EMAIL,
      name: 'LandlordReviews'
    },
    subject: 'Reset your password',
    html: `
      <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif;">
        <h2 style="color: #333;">Password Reset Request</h2>
        
        <p>Hi ${firstName},</p>
        
        <p>We received a request to reset your password. Click the button below to create a new password:</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" 
             style="background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Reset Password
          </a>
        </div>
        
        <p>If you didn't request this password reset, you can safely ignore this email. Your password will not be changed.</p>
        
        <p style="margin-top: 30px; color: #666; font-size: 14px;">
          This reset link will expire in 1 hour for security reasons.
        </p>
      </div>
    `
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ Password reset email sent to ${email}`);
  } catch (error) {
    console.error('❌ Password reset email failed:', error);
    throw new Error('Failed to send password reset email');
  }
};

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail
};