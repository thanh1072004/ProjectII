const jwt = require('jsonwebtoken')

const requireAuth = (req, res, next) => {
    const token = req.cookies.accessToken;
    if (!token) return res.status(401).json({error: 'Unauthorized, please login!'});
    try { 
        const deocded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = deocded;
        next();
    }catch (err) {
        return res.status(401).json({error: 'Token verification failed'}); 
    }
}

const requireManager = (req, res, next) => {
    const token = req.cookies.accessToken;
    if (!token) return res.status(401).json({error: 'Unauthorized, please login!'});
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        if (req.user.role != 'manager') return res.status(401).json({error : 'Unauthorized, not manager'});
        next();
    }catch (err){ 
        return res.status(401).json({error: 'Token verification failed'});
    }
}

module.exports = {
    requireAuth,
    requireManager,
}