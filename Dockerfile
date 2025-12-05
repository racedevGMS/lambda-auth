FROM public.ecr.aws/lambda/python:3.11

# Copy requirements and install dependencies
COPY requirements.txt ${LAMBDA_TASK_ROOT}
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ${LAMBDA_TASK_ROOT}/

# Set the CMD to your handler
CMD ["main.handler"]