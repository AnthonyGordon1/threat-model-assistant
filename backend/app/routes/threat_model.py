import csv
import io
import json
from fastapi import APIRouter, HTTPException, Security, Depends
from app.models.schemas import ThreatModelRequest, ThreatModelResponse, Threat
from app.services.rag import run_rag_pipeline
from app.services.guardrails import check_input, check_output
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request
from app.services.auth import verify_api_key

router = APIRouter()

limiter = Limiter(key_func=get_remote_address)


@router.post("/analyze", response_model=ThreatModelResponse)
@limiter.limit("10/minute")
async def analyze(request: Request, body: ThreatModelRequest, 
                  api_key: str = Security(verify_api_key)):    
    try:
        # Step 1: Check input for prompt injection
        check_input(f"{body.architecture} {body.feature}")
        # Step 2: Run the RAG pipeline
        raw_response = run_rag_pipeline(body.architecture, body.feature)
        # Step 3: Check and clean the output
        clean_threats = check_output(raw_response)

        return ThreatModelResponse(
            threats=[Threat(**t) for t in clean_threats],
            raw_response=raw_response
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/export/csv")
async def export_csv(response: ThreatModelResponse):
    try:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "threat", "category", "likelihood", "mitigation", "mitre_mapping"
        ])
        writer.writeheader()
        for threat in response.threats:
            writer.writerow({
                "threat": threat.threat,
                "category": threat.category,
                "likelihood": threat.likelihood,
                "mitigation": threat.mitigation,
                "mitre_mapping": threat.mitre_mapping or ""
            })
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threat_model.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export/pdf")
async def export_pdf(response: ThreatModelResponse):
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
            rightMargin=inch, leftMargin=inch,
            topMargin=inch, bottomMargin=inch)

        styles = getSampleStyleSheet()
        elements = []

        elements.append(Paragraph("Threat Model Report", styles['Title']))
        elements.append(Spacer(1, 20))

        table_data = [["Threat", "Category", "Likelihood", "Mitigation", "MITRE"]]
        for t in response.threats:
            table_data.append([
                Paragraph(t.threat, styles['Normal']),
                Paragraph(t.category, styles['Normal']),
                Paragraph(t.likelihood, styles['Normal']),
                Paragraph(t.mitigation, styles['Normal']),
                Paragraph(t.mitre_mapping or "", styles['Normal']),
            ])

        table = Table(table_data, colWidths=[1.2*inch, 1*inch, 0.8*inch, 2.5*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0a0e17')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00e5a0')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f5f5f5'), colors.white]),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(table)
        doc.build(elements)
        buffer.seek(0)

        return StreamingResponse(
            iter([buffer.getvalue()]),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=threat_model.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))