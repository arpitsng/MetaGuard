# =================================================================
# MetaGuard v1.2 - Self-Contained Full-Stack App
# =================================================================

import os
import uvicorn
import tempfile
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Import our engine
import main as engine

# --- FastAPI App Initialization ---
app = FastAPI(
    title="MetaGuard API",
    description="An all-in-one file forensics tool with built-in UI.",
    version="1.2.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- API Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def get_root():
    """Serve the main HTML page"""
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: index.html not found</h1>")

@app.post("/analyze/")
async def analyze_file(file: UploadFile = File(...)):
    """Full analysis endpoint"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as temp:
        temp.write(await file.read())
        temp_path = temp.name

    analysis_results = {"filename": file.filename}

    try:
        # True file type
        type_info = engine.get_true_file_type(temp_path)
        analysis_results['true_type_analysis'] = type_info
        
        mime_type = type_info.get("mime_type", "")

        # Metadata extraction & risk analysis
        metadata = {}
        if 'image' in mime_type:
            metadata = engine.extract_image_metadata(temp_path)
            analysis_results['metadata_risks'] = engine.analyze_metadata_risks(metadata, 'image')
        elif 'pdf' in mime_type:
            metadata = engine.extract_pdf_metadata(temp_path)
            analysis_results['metadata_risks'] = engine.analyze_metadata_risks(metadata, 'pdf')
        analysis_results['metadata'] = metadata

        # Advanced analysis
        if 'image' in mime_type:
            analysis_results['steganography_report'] = engine.detect_lsb_steganography(temp_path)
        if 'zip' in mime_type:
            analysis_results['macro_report'] = engine.check_for_macros(temp_path)
        if 'pdf' in mime_type:
            analysis_results['embedded_urls'] = engine.find_urls_in_pdf(temp_path)
        
        # VirusTotal check
        analysis_results['virustotal_report'] = engine.check_virustotal(temp_path)

    finally:
        os.unlink(temp_path)

    return JSONResponse(content=analysis_results)

@app.post("/clean/")
async def clean_file(file: UploadFile = File(...)):
    """Clean metadata from a file and return the cleaned version"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as temp_source:
        temp_source.write(await file.read())
        temp_source_path = temp_source.name

    base, ext = os.path.splitext(temp_source_path)
    temp_output_path = f"{base}_cleaned{ext}"

    try:
        success = False
        mime_type = engine.get_true_file_type(temp_source_path).get("mime_type", "")

        if 'image' in mime_type:
            success = engine.clean_image_metadata(temp_source_path, temp_output_path)
        elif 'pdf' in mime_type:
            success = engine.clean_pdf_metadata(temp_source_path, temp_output_path)
        
        if success and os.path.exists(temp_output_path):
            cleaned_filename = f"{os.path.splitext(file.filename)[0]}_cleaned{os.path.splitext(file.filename)[1]}"
            return FileResponse(
                path=temp_output_path, 
                filename=cleaned_filename,
                media_type='application/octet-stream'
            )
        else:
            return JSONResponse(status_code=400, content={"error": "Could not clean the file or unsupported file type."})

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Cleaning failed: {str(e)}"})
    finally:
        # Cleanup
        if os.path.exists(temp_source_path):
            os.unlink(temp_source_path)
        # Note: temp_output_path is cleaned up by FileResponse

@app.post("/destroy-steg/")
async def destroy_steganography_endpoint(file: UploadFile = File(...)):
    """Destroy potential steganography and return the processed file"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as temp_source:
        temp_source.write(await file.read())
        temp_source_path = temp_source.name

    base, ext = os.path.splitext(temp_source_path)
    temp_output_path = f"{base}_steg_destroyed{ext}"

    try:
        success = engine.destroy_steganography(temp_source_path, temp_output_path)
        
        if success and os.path.exists(temp_output_path):
            cleaned_filename = f"{os.path.splitext(file.filename)[0]}_steg_destroyed{os.path.splitext(file.filename)[1]}"
            return FileResponse(
                path=temp_output_path, 
                filename=cleaned_filename,
                media_type='application/octet-stream'
            )
        else:
            return JSONResponse(status_code=400, content={"error": "Could not destroy steganography or unsupported file type."})

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Steganography destruction failed: {str(e)}"})
    finally:
        if os.path.exists(temp_source_path):
            os.unlink(temp_source_path)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)