import { NextFunction, Response } from 'express';
import jwt from 'jsonwebtoken';
import { AuthenticatedRequest } from '../controller/ProjectController'; // Убедитесь, что путь правильный

const secretKey = 'your_secret_key';  // Секретный ключ для подписи JWT, должен быть надежным и секретным

export const authMiddleware = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).send('Authorization header is missing');
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).send('Token is missing');
    }

    try {
        const decoded = jwt.verify(token, secretKey) as { userId: string };
        req.userId = decoded.userId;
        next();
    } catch (err) {
        return res.status(401).send('Invalid token');
    }
};