const cors = require('cors'); app.use(cors({ origin: '*' })); app.use('/files', serveIndex('public'));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(doc));
