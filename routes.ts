import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { 
  userLoginSchema, 
  userRegisterSchema, 
  createJobSchema, 
  insertApplicationSchema, 
  insertReferralSchema, 
  insertSavedJobSchema
} from "@shared/schema";
import { AIRecommendationService } from './services/ai-recommendation';
import { ChatService } from './services/chat-service';
import path from "path";
import multer from "multer";
import fs from "fs";
import { ZodError } from "zod";

// Setup multer for file uploads
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const fileStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, uploadDir);
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
  }
});

// Image uploads configuration
const imageUpload = multer({ 
  storage: fileStorage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max file size
  },
  fileFilter: (_req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.') as any);
    }
  }
});

// Document uploads configuration
const documentUpload = multer({
  storage: fileStorage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max file size for documents
  },
  fileFilter: (_req, file, cb) => {
    const allowedTypes = [
      'application/pdf', 
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/msword'
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF and DOCX files are allowed.') as any);
    }
  }
});

// Helper function to serve uploaded files
const serveUploads = (app: Express) => {
  app.use('/uploads', express.static(path.join(process.cwd(), "uploads")));
};

// Error handler for routes
const handleError = (res: Response, error: unknown) => {
  console.error('API Error:', error);
  
  if (error instanceof ZodError) {
    return res.status(400).json({ 
      message: 'Validation error', 
      errors: error.errors 
    });
  }
  
  return res.status(500).json({ 
    message: error instanceof Error ? error.message : 'An unexpected error occurred'
  });
};

// Authentication middleware
const requireAuth = (req: Request, res: Response, next: Function) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  next();
};

import express from 'express';
import session from 'express-session';
import memorystore from 'memorystore';

export async function registerRoutes(app: Express): Promise<Server> {
  // Setup sessions
  const MemoryStore = memorystore(session);
  app.use(session({
    secret: process.env.SESSION_SECRET || 'jobconnect-secret-key',
    resave: false,
    saveUninitialized: false,
    store: new MemoryStore({
      checkPeriod: 86400000 // prune expired entries every 24h
    }),
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
  }));
  
  // Serve uploaded files
  serveUploads(app);
  
  // Auth routes
  app.post('/api/auth/register', async (req, res) => {
    try {
      const userData = userRegisterSchema.parse(req.body);
      
      // Check if username already exists
      const existingUsername = await storage.getUserByUsername(userData.username);
      if (existingUsername) {
        return res.status(400).json({ message: 'Username already exists' });
      }
      
      // Check if email already exists
      const existingEmail = await storage.getUserByEmail(userData.email);
      if (existingEmail) {
        return res.status(400).json({ message: 'Email already exists' });
      }
      
      // Create user (in a real app, password would be hashed)
      const { confirmPassword, ...userToCreate } = userData;
      const user = await storage.createUser(userToCreate);
      
      // Set session
      req.session.userId = user.id;
      
      // Return user without password
      const { password, ...userWithoutPassword } = user;
      res.status(201).json(userWithoutPassword);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.post('/api/auth/login', async (req, res) => {
    try {
      const credentials = userLoginSchema.parse(req.body);
      
      const user = await storage.getUserByUsername(credentials.username);
      if (!user || user.password !== credentials.password) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }
      
      // Set session
      req.session.userId = user.id;
      
      // Return user without password
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ message: 'Logout failed' });
      }
      res.json({ message: 'Logged out successfully' });
    });
  });
  
  app.get('/api/auth/me', async (req, res) => {
    try {
      if (!req.session.userId) {
        return res.status(401).json({ message: 'Not authenticated' });
      }
      
      const user = await storage.getUser(req.session.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      // Return user without password
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  // User routes
  app.get('/api/users/:id', async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      // Return user without password
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.put('/api/users/profile', requireAuth, imageUpload.single('profileImage'), async (req, res) => {
    try {
      const userId = req.session.userId!;
      const userData = req.body;
      
      // Add profile image path if uploaded
      if (req.file) {
        userData.profileImage = `/uploads/${req.file.filename}`;
      }
      
      const updatedUser = await storage.updateUser(userId, userData);
      if (!updatedUser) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      // Return user without password
      const { password, ...userWithoutPassword } = updatedUser;
      res.json(userWithoutPassword);
    } catch (error) {
      handleError(res, error);
    }
  });

  // Verification request endpoint
  app.post('/api/users/request-verification', requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId!;
      
      // Get current user data
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      // Validate verification data based on user type
      if (user.userType === 'individual' && !user.mobileNumber) {
        return res.status(400).json({ message: 'Mobile number is required for individual verification' });
      }
      
      if (user.userType === 'organization' && 
          (!user.companyName || !user.companyGst || !user.companyMobileNumber)) {
        return res.status(400).json({ 
          message: 'Company name, GST number, and mobile number are required for organization verification' 
        });
      }
      
      // In a real app, this would initiate a verification process
      // For now, we'll just update the user's verification status
      // In a production app, this would involve sending a verification code by SMS
      // or initiating a more complex verification flow
      
      const updatedUser = await storage.updateUser(userId, { 
        // For demo purposes, we're setting this to false
        // In a real app, it would start as false and then be verified
        isVerified: false 
      });
      
      if (!updatedUser) {
        return res.status(404).json({ message: 'Failed to update user verification status' });
      }
      
      // Return user without password
      const { password, ...userWithoutPassword } = updatedUser;
      res.json(userWithoutPassword);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  // Job routes
  app.get('/api/jobs', async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 20;
      const offset = req.query.offset ? parseInt(req.query.offset as string) : 0;
      
      let jobs;
      
      // Check if we have filters
      if (req.query.search || req.query.skills || req.query.location || req.query.employmentType) {
        const filters = {
          search: req.query.search as string | undefined,
          skills: req.query.skills ? (req.query.skills as string).split(',') : undefined,
          location: req.query.location as string | undefined,
          employmentType: req.query.employmentType as string | undefined
        };
        
        jobs = await storage.getJobsWithFilters(filters);
      } else {
        jobs = await storage.getJobsWithUser(limit, offset);
      }
      
      res.json(jobs);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.get('/api/jobs/:id', async (req, res) => {
    try {
      const jobId = parseInt(req.params.id);
      const job = await storage.getJobWithUser(jobId);
      
      if (!job) {
        return res.status(404).json({ message: 'Job not found' });
      }
      
      res.json(job);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.post('/api/jobs', requireAuth, imageUpload.single('image'), async (req, res) => {
    try {
      const userId = req.session.userId!;
      
      // Parse skills as an array if it comes as a string
      if (typeof req.body.skills === 'string') {
        req.body.skills = req.body.skills.split(',').map((s: string) => s.trim());
      }
      
      const jobData = createJobSchema.parse({
        ...req.body,
        userId
      });
      
      // Add image path if uploaded
      if (req.file) {
        jobData.imageUrl = `/uploads/${req.file.filename}`;
      }
      
      const job = await storage.createJob(jobData);
      res.status(201).json(job);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.put('/api/jobs/:id', requireAuth, imageUpload.single('image'), async (req, res) => {
    try {
      const jobId = parseInt(req.params.id);
      const userId = req.session.userId!;
      
      // Check if job exists and belongs to user
      const existingJob = await storage.getJob(jobId);
      if (!existingJob) {
        return res.status(404).json({ message: 'Job not found' });
      }
      
      if (existingJob.userId !== userId) {
        return res.status(403).json({ message: 'You can only update your own job posts' });
      }
      
      // Parse skills as an array if it comes as a string
      if (typeof req.body.skills === 'string') {
        req.body.skills = req.body.skills.split(',').map((s: string) => s.trim());
      }
      
      let jobData = req.body;
      
      // Add image path if uploaded
      if (req.file) {
        jobData.imageUrl = `/uploads/${req.file.filename}`;
      }
      
      const updatedJob = await storage.updateJob(jobId, jobData);
      if (!updatedJob) {
        return res.status(404).json({ message: 'Job not found' });
      }
      
      res.json(updatedJob);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.delete('/api/jobs/:id', requireAuth, async (req, res) => {
    try {
      const jobId = parseInt(req.params.id);
      const userId = req.session.userId!;
      
      // Check if job exists and belongs to user
      const existingJob = await storage.getJob(jobId);
      if (!existingJob) {
        return res.status(404).json({ message: 'Job not found' });
      }
      
      if (existingJob.userId !== userId) {
        return res.status(403).json({ message: 'You can only delete your own job posts' });
      }
      
      const deleted = await storage.deleteJob(jobId);
      if (!deleted) {
        return res.status(404).json({ message: 'Job not found' });
      }
      
      res.json({ message: 'Job deleted successfully' });
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.get('/api/jobs/user/posted', requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId!;
      const jobs = await storage.getUserJobs(userId);
      res.json(jobs);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  // Application routes
  app.post('/api/applications', requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId!;
      
      const applicationData = insertApplicationSchema.parse({
        ...req.body,
        userId
      });
      
      // Check if user already applied
      const userApplications = await storage.getUserApplications(userId);
      const alreadyApplied = userApplications.some(app => app.jobId === applicationData.jobId);
      
      if (alreadyApplied) {
        return res.status(400).json({ message: 'You have already applied for this job' });
      }
      
      const application = await storage.createApplication(applicationData);
      res.status(201).json(application);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.get('/api/applications/user', requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId!;
      const applications = await storage.getUserApplications(userId);
      
      // Get job details for each application
      const applicationsWithJobs = await Promise.all(
        applications.map(async (app) => {
          const job = await storage.getJob(app.jobId);
          return { ...app, job };
        })
      );
      
      res.json(applicationsWithJobs);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  // Referral routes
  app.post('/api/referrals', requireAuth, async (req, res) => {
    try {
      const referrerId = req.session.userId!;
      
      const referralData = insertReferralSchema.parse({
        ...req.body,
        referrerId
      });
      
      const referral = await storage.createReferral(referralData);
      res.status(201).json(referral);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.get('/api/referrals/user', requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId!;
      const referrals = await storage.getUserReferrals(userId);
      
      // Get job and user details for each referral
      const referralsWithDetails = await Promise.all(
        referrals.map(async (ref) => {
          const job = await storage.getJob(ref.jobId);
          const referrer = await storage.getUser(ref.referrerId);
          const referree = await storage.getUser(ref.referreeId);
          
          return { 
            ...ref, 
            job,
            referrer: referrer ? { 
              id: referrer.id, 
              username: referrer.username, 
              fullName: referrer.fullName,
              profileImage: referrer.profileImage 
            } : null,
            referree: referree ? { 
              id: referree.id, 
              username: referree.username, 
              fullName: referree.fullName,
              profileImage: referree.profileImage 
            } : null
          };
        })
      );
      
      res.json(referralsWithDetails);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.put('/api/referrals/:id/status', requireAuth, async (req, res) => {
    try {
      const referralId = parseInt(req.params.id);
      const { status } = req.body;
      
      if (!status || !['accepted', 'rejected', 'pending'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status. Must be accepted, rejected, or pending' });
      }
      
      const updatedReferral = await storage.updateReferral(referralId, status);
      if (!updatedReferral) {
        return res.status(404).json({ message: 'Referral not found' });
      }
      
      res.json(updatedReferral);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  // Saved Jobs routes
  app.post('/api/saved-jobs', requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId!;
      
      const savedJobData = insertSavedJobSchema.parse({
        ...req.body,
        userId
      });
      
      const savedJob = await storage.createSavedJob(savedJobData);
      res.status(201).json(savedJob);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.delete('/api/saved-jobs/:jobId', requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId!;
      const jobId = parseInt(req.params.jobId);
      
      const deleted = await storage.deleteSavedJob(userId, jobId);
      if (!deleted) {
        return res.status(404).json({ message: 'Saved job not found' });
      }
      
      res.json({ message: 'Job removed from saved list' });
    } catch (error) {
      handleError(res, error);
    }
  });
  
  app.get('/api/saved-jobs', requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId!;
      const savedJobs = await storage.getUserSavedJobs(userId);
      res.json(savedJobs);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  // AI Recommendation and document upload routes
  // Initialize the AI recommendation service
  const aiRecommendationService = new AIRecommendationService(storage);

  // Resume upload and processing route
  app.post('/api/resume-upload', requireAuth, documentUpload.single('resume'), async (req, res) => {
    try {
      const userId = req.session.userId!;
      
      // Check if file was uploaded
      if (!req.file) {
        return res.status(400).json({ message: 'No resume file uploaded' });
      }
      
      // Process resume to extract skills and experience
      const filePath = req.file.path;
      const resumeData = await aiRecommendationService.processResume(filePath);
      
      // Update user profile with skills from resume
      await aiRecommendationService.updateUserProfileFromResume(userId, resumeData);
      
      // Get job recommendations based on resume data
      const recommendations = await aiRecommendationService.getRecommendations(userId, resumeData);
      
      res.json({ 
        message: 'Resume processed successfully',
        resumeData,
        recommendations
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  // Get personalized job recommendations
  app.get('/api/recommendations', requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId!;
      const recommendations = await aiRecommendationService.getRecommendations(userId);
      res.json(recommendations);
    } catch (error) {
      handleError(res, error);
    }
  });

  // Document upload in chat
  app.post('/api/chat/documents', requireAuth, documentUpload.single('document'), async (req, res) => {
    try {
      const userId = req.session.userId!;
      
      // Check if file was uploaded
      if (!req.file) {
        return res.status(400).json({ message: 'No document uploaded' });
      }
      
      // Process document based on file type
      const filePath = req.file.path;
      const fileUrl = `/uploads/${req.file.filename}`;
      const fileType = req.file.mimetype;
      
      // For PDF/DOCX files, process and extract content
      if (fileType === 'application/pdf' || 
          fileType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
          fileType === 'application/msword') {
        try {
          // Process resume to extract skills and experience
          const resumeData = await aiRecommendationService.processResume(filePath);
          
          return res.json({
            message: 'Document processed successfully',
            fileUrl,
            fileName: req.file.originalname,
            fileType,
            resumeData
          });
        } catch (processingError) {
          console.error('Error processing document:', processingError);
          // Return basic file info even if processing fails
          return res.json({
            message: 'Document uploaded but could not be fully processed',
            fileUrl,
            fileName: req.file.originalname,
            fileType
          });
        }
      }
      
      // For all other document types, just return the URL
      res.json({
        message: 'Document uploaded successfully',
        fileUrl,
        fileName: req.file.originalname,
        fileType
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  // Setup HTTP server
  const httpServer = createServer(app);
  
  // Initialize chat service with WebSockets
  const chatService = new ChatService(httpServer, storage);
  
  // WebSocket authentication endpoint
  app.post('/api/chat/auth', requireAuth, (req, res) => {
    try {
      const userId = req.session.userId!;
      // Generate a token for WebSocket authentication
      const token = `${userId}_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
      
      // In a real app, you would store this token securely
      // For demo purposes, we'll just send it back
      res.json({ token });
    } catch (error) {
      handleError(res, error);
    }
  });
  
  // Chat endpoints for fetching message history (would be implemented in a real app)
  app.get('/api/chat/messages/:recipientId', requireAuth, (req, res) => {
    try {
      const userId = req.session.userId!;
      const recipientId = parseInt(req.params.recipientId);
      
      // In a real app, you would fetch message history from the database
      // For demo purposes, we'll return an empty array
      res.json([]);
    } catch (error) {
      handleError(res, error);
    }
  });
  
  return httpServer;
}
