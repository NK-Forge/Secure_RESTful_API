const express = require('express');
const router = express.Router();
const Resource = require('../models/Resource');
const { protect, authorize } = require('../middlewares/auth');
const { createError } = require('../utils/errorHandler');

// Create a new resource - authenticated users only
router.post('/', protect, async (req, res, next) => {
    try {
        const resource = await Resource.create({
            ...req.body,
            owner: req.user.id
        });

        res.status(201).json({
            success: true,
            data: resource
        });
    }   catch (error) {
        next(error);
    }
});

// Get all resources (with access control)
router.get('/', protect, async (req, res, next) => {
    try {
        const query = {};

        // Admin can see all resources
        if (!req.user.roles.includes('adimin')) {
            // Users can see public resources, their own resources, or resources they have explicit access to
            query.$or = [
                { accessLevel: 'public' },
                { owner: req.user.id },
                { allowedUsers: req.user.roles },
                {
                  accessLevel: 'restricted',
                  allowedRoles: { $in: req.user.roles }
                }
            ];
        }

        const resources = await Resource.find(query);
        
        res.status(200).json({
            success: true,
            count: resources.length,
            data: resources
        });
    }   catch (error) {
        next(error);
    }
});

// Get a single resource
router.get('/:id', protect, async (req, res, next) => {
    try {
        const resource = await Resource.findById(req.params.id);
        if (!resource) {
            return next(createError(404, 'Resource not found'));
        }

        // Check if user has access to this resource
        const hasAccess =
            resource.accessLevel === 'public' ||
            resource.owner.toString() === req.user.id ||
            resource.allowedUsers.includes(req.user.id) ||
            (resource.accessLevel === 'restricted' &&
             resource.allowedRoles.some(role => req.user.roles.includes(role))) ||
            req.user.roles.includes('admin');
        
        
        if (!hasAccess) {
            return next(createError(403, "Not authorized to access this resource"));
        }

        res.status(200).json({
            success: true,
            data: resource
        });        
    }   catch (error) {
        next(error);
    }
});


// Update resource - owner or admin only
router.put('/:id', protect, async (req, res, next) => {
    try {
        let resource = await Resource.findById(req.params.id);

        if (!resource) {
            return next(createError(404, 'Resource not found'));
        }

        // Check ownership or admin status
        if (resource.owner.toString() !== req.user.id && !req.user.roles.includes('admin')) {
            return next(createError(403, 'Not authorized to update this resource'));
        }

        // Update resource
        resource = await Resource.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true, runValidators: true }
        );

        res.status(200).json({
            success: true,
            data: resource
        });
    }   catch (error) {
        next(error);
    }
});


// Delete resource - owner or admin only
router.delete('/:id', protect, async (req, res, next) => {
    try {
        const resource = await Resource.findById(req.params.id);

        if (!resource) {
            return next(createError(404, 'Resource not found'));
        }

        // Check ownership or admin status
        if (resource.owner.toString() !== req.user.id && !req.user.roles.includes('admin')) {
            return next(createError(403, 'Not authorized to delete this resource'));
        }

        await resource.remove();

        res.status(200).json({
            success: true,
            data: {}
        });
    }   catch (error) {
        next(error);
    }
});

// Grant access to a resource - owner or admin only
router.post('/:id/access', protect, async (req, res, next) => {
    try {
        const { userId, role } = req.body;
        const resource = await Resource.findById(req.params.id);

        if (!resource) {
            return next(createError(404, 'Resource not found'));
        }

        // Check ownership or admin status
        if (resource.owner.toString() !== req.user.id && !req.user.roles.includes('admin')) {
            return next(createError(403, 'Not authorized to modify access for this resource'));
        }

        // Add user to allowed users if provided
        if (userId && !resource.allowedUsers.includes(userId)) {
            resource.allowedUsers.push(userId);
        }

        // Add role to allowed roles if provided
        if (role && !resource.allowedRoles.includes(role)) {
            resource.allowedRoles.push(role);
        }

        await resource.save();

        res.status(200).json({
            success: true,
            data: resource
        });
    }   catch (error) {
        next(error);
    }
});


// Revoke access to a resource - owner or admin only
router.delete('/:id/access', protect, async (req, res, next) => {
    try {
        const { userId, role } = req.body;
        const resource = await Resource.findById(req.params.id);

        if (!resource) {
            return next(createError(404, 'Resource not found'));
        }


        // Check ownership or admin status
        if (resource.owner.toString() !== req.user.id && !req.user.roles.includes('admin')) {
            return next(createError(403, 'Not authorized to modify access for this resource'));
        }


        // Remove user from allowed users if provided
        if (userId) {
            resource.allowedUsers = resource.allowedUsers.filter(
                id => id.toString() !== userId
            );
        }


        // Remove role from allowed roles if provided
        if (role) {
            resource.allowedRoles = resource.allowedRoles.filter(r => r !== role);
        }

        await resource.save();

        res.status(200).json({
            success: true,
            data: resource
        });
    }   catch (error) {
        next(error);
    }
});

module.exports = router;