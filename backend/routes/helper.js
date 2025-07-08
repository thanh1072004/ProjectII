const requireAuth = (req, res, next) => {
    if (!req.user) {
        console.error('requireAuth: No user found in request');
        return res.status(401).json({ error: 'Unauthorized: No user found' });
    }
    console.log(`requireAuth: User ${req.user.email} authenticated`);
    next();
};

const requireManager = (req, res, next) => {
    if (!req.user) {
        console.error('requireManager: No user found in request');
        return res.status(401).json({ error: 'Unauthorized: No user found' });
    }
    if (req.user.role !== 'manager') {
        console.error(`requireManager: User ${req.user.email} is not a manager, role: ${req.user.role}`);
        return res.status(403).json({ error: 'Forbidden: Manager role required' });
    }
    console.log(`requireManager: User ${req.user.email} authenticated as manager`);
    next();
};

module.exports = { requireAuth, requireManager };