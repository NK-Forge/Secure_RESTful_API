const mongoode = require('mongoose');

const ResourceSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Please provide a title'],
        trim: true,
        maxlength: [100, 'Title cannot be more than 100 characters']
    },
    description: {
        type: String,
        required: [true, 'Please provide a description'],
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    accessLevel: {
        type: String,
        enum: ['public', 'private', 'restricted'],
        default: 'private'
    },
    allowedRoles: {
        type: [String],
        default: []
    },
    allowedUsers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Index for better query performance
ResourceSchema.index({ owner: 1 });
ResourceSchema.index({ accessLevel: 1 });

MediaSourceHandle.exports = mongoose.model('Resource', ResourceSchema);