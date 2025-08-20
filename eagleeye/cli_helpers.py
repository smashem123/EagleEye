"""
Helper functions for CLI commands
"""
import asyncio
import json
from pathlib import Path
from typing import Optional
from rich.table import Table
from rich.panel import Panel
from rich import box

from .analysis import TextAnalyzer, ContentScraper, NLPPipeline
from .ui import EagleEyeUI


async def _run_text_analysis(
    text: Optional[str],
    url: Optional[str], 
    email_file: Optional[str],
    output_format: str,
    ui: EagleEyeUI
):
    """Run text analysis with various input sources"""
    analyzer = TextAnalyzer()
    scraper = ContentScraper()
    nlp = NLPPipeline()
    
    results = []
    
    try:
        # Analyze direct text input
        if text:
            with ui.console.status("[bold green]Analyzing text content..."):
                result = await analyzer.analyze_text(text, source_type="direct_input")
                nlp_result = await nlp.comprehensive_analysis(text)
                
                combined_result = {
                    'source': 'direct_input',
                    'text_analysis': result.to_dict(),
                    'nlp_analysis': nlp_result
                }
                results.append(combined_result)
        
        # Analyze URL content
        if url:
            with ui.console.status(f"[bold green]Scraping and analyzing URL: {url}"):
                scraped_content = await scraper.scrape_url(url)
                
                if scraped_content.get('content'):
                    result = await analyzer.analyze_text(
                        scraped_content['content'], 
                        source_url=url,
                        source_type="website"
                    )
                    nlp_result = await nlp.comprehensive_analysis(scraped_content['content'])
                    
                    combined_result = {
                        'source': 'website',
                        'url': url,
                        'scraped_data': scraped_content,
                        'text_analysis': result.to_dict(),
                        'nlp_analysis': nlp_result
                    }
                    results.append(combined_result)
                else:
                    ui.print_error(f"Could not extract content from URL: {url}")
        
        # Analyze email file
        if email_file:
            email_path = Path(email_file)
            if not email_path.exists():
                ui.print_error(f"Email file not found: {email_file}")
                return
            
            with ui.console.status(f"[bold green]Analyzing email file: {email_file}"):
                with open(email_path, 'r', encoding='utf-8', errors='ignore') as f:
                    email_content = f.read()
                
                parsed_email = scraper.parse_email_content(email_content)
                
                if parsed_email.get('content'):
                    result = await analyzer.analyze_text(
                        parsed_email['content'],
                        source_type="email"
                    )
                    nlp_result = await nlp.comprehensive_analysis(parsed_email['content'])
                    
                    combined_result = {
                        'source': 'email',
                        'file_path': str(email_path),
                        'email_data': parsed_email,
                        'text_analysis': result.to_dict(),
                        'nlp_analysis': nlp_result
                    }
                    results.append(combined_result)
                else:
                    ui.print_error(f"Could not extract content from email: {email_file}")
        
        # Display results
        if results:
            if output_format.lower() == 'json':
                ui.console.print_json(json.dumps(results, indent=2, default=str))
            else:
                _display_analysis_results(results, ui)
        else:
            ui.print_error("No content could be analyzed")
            
    except Exception as e:
        ui.print_error(f"Analysis failed: {e}")


def _display_analysis_results(results: list, ui: EagleEyeUI):
    """Display text analysis results in table format"""
    
    for i, result in enumerate(results):
        text_analysis = result.get('text_analysis', {})
        nlp_analysis = result.get('nlp_analysis', {})
        
        # Create summary table
        table = Table(
            title=f"Analysis Result {i+1}: {result['source'].title()}",
            title_style="bold cyan",
            border_style="cyan",
            box=box.ROUNDED
        )
        
        table.add_column("Metric", style="bold white", width=20)
        table.add_column("Value", style="green", width=30)
        table.add_column("Details", style="yellow", width=40)
        
        # Basic info
        if result['source'] == 'website':
            table.add_row("URL", result.get('url', 'N/A'), "Source website")
        elif result['source'] == 'email':
            email_data = result.get('email_data', {})
            table.add_row("Subject", email_data.get('subject', 'N/A'), "Email subject line")
            table.add_row("From", email_data.get('headers', {}).get('from', 'N/A'), "Sender address")
        
        # Scam detection results
        scam_type = text_analysis.get('scam_type', 'unknown')
        confidence = text_analysis.get('confidence', 0.0)
        risk_score = text_analysis.get('risk_score', 0.0)
        
        table.add_row("Scam Type", scam_type.title(), f"Detected scam category")
        table.add_row("Confidence", f"{confidence:.1%}", f"Detection confidence level")
        table.add_row("Risk Score", f"{risk_score:.1f}/10", f"Overall threat level")
        
        # NLP results
        classification = nlp_analysis.get('classification', {})
        ml_prediction = classification.get('predicted_class', 'unknown')
        ml_confidence = classification.get('confidence', 0.0)
        
        table.add_row("ML Prediction", ml_prediction.title(), f"Machine learning classification")
        table.add_row("ML Confidence", f"{ml_confidence:.1%}", f"ML model confidence")
        
        # Sentiment analysis
        sentiment = nlp_analysis.get('sentiment', {})
        emotion = sentiment.get('emotion', 'neutral')
        urgency = sentiment.get('urgency_score', 0.0)
        
        table.add_row("Emotion", emotion.title(), f"Detected emotional tone")
        table.add_row("Urgency", f"{urgency:.1%}", f"Urgency/pressure level")
        
        # Pattern analysis
        patterns = nlp_analysis.get('language_patterns', {})
        urgency_markers = patterns.get('urgency_markers', 0)
        financial_requests = patterns.get('financial_requests', 0)
        
        table.add_row("Urgency Markers", str(urgency_markers), f"Urgent language indicators")
        table.add_row("Financial Requests", str(financial_requests), f"Money/account requests")
        
        # Composite risk
        composite_risk = nlp_analysis.get('composite_risk_score', 0.0)
        table.add_row("Composite Risk", f"{composite_risk:.1f}/10", f"Combined AI risk assessment")
        
        ui.console.print(table)
        ui.console.print()
        
        # Show suspicious patterns if any
        suspicious_patterns = text_analysis.get('suspicious_patterns', [])
        if suspicious_patterns:
            patterns_panel = Panel(
                "\n".join([f"• {pattern}" for pattern in suspicious_patterns[:10]]),
                title="🚨 Suspicious Patterns Detected",
                title_align="left",
                border_style="red"
            )
            ui.console.print(patterns_panel)
            ui.console.print()
        
        # Show extracted entities
        entities = nlp_analysis.get('entities', [])
        financial_entities = [e for e in entities if e['label'] in ['CREDIT_CARD', 'SSN', 'ACCOUNT_NUMBER', 'MONEY', 'EMAIL', 'PHONE']]
        
        if financial_entities:
            entity_table = Table(
                title="💳 Financial/Personal Data Detected",
                title_style="bold red",
                border_style="red",
                box=box.SIMPLE
            )
            entity_table.add_column("Type", style="bold red")
            entity_table.add_column("Value", style="yellow")
            entity_table.add_column("Confidence", style="green")
            
            for entity in financial_entities[:5]:  # Show first 5
                entity_table.add_row(
                    entity['label'],
                    entity['text'][:20] + "..." if len(entity['text']) > 20 else entity['text'],
                    f"{entity.get('confidence', 0.8):.1%}"
                )
            
            ui.console.print(entity_table)
            ui.console.print()
        
        # Risk assessment summary
        if composite_risk >= 7.0:
            risk_level = "🔴 HIGH RISK"
            risk_color = "red"
        elif composite_risk >= 4.0:
            risk_level = "🟡 MEDIUM RISK"
            risk_color = "yellow"
        else:
            risk_level = "🟢 LOW RISK"
            risk_color = "green"
        
        summary_panel = Panel(
            f"[bold {risk_color}]{risk_level}[/bold {risk_color}]\n\n"
            f"This content shows characteristics of {scam_type} with {confidence:.0%} confidence.\n"
            f"Combined AI analysis indicates a risk level of {composite_risk:.1f}/10.",
            title="🛡️ Risk Assessment Summary",
            title_align="center",
            border_style=risk_color
        )
        ui.console.print(summary_panel)
        
        if i < len(results) - 1:
            ui.console.print("\n" + "─" * 80 + "\n")


async def _run_report_submission(
    text: Optional[str],
    voice: Optional[str],
    url: Optional[str],
    email: Optional[str],
    location: Optional[str],
    description: str,
    ui
):
    """Handle user scam report submission"""
    from .crowdsource import ScamReporter
    import uuid
    
    reporter = ScamReporter()
    user_id = str(uuid.uuid4())[:8]  # Generate anonymous user ID
    
    try:
        report = None
        
        if text:
            with ui.console.status("[bold green]Submitting text report..."):
                report = await reporter.submit_text_report(
                    user_id=user_id,
                    content=text,
                    source_info={'type': 'direct_text', 'description': description},
                    location=location
                )
        
        elif voice:
            with ui.console.status("[bold green]Analyzing voice report..."):
                report = await reporter.submit_voice_report(
                    user_id=user_id,
                    audio_file_path=voice,
                    source_info={'type': 'voice_call', 'description': description},
                    location=location
                )
        
        elif url:
            with ui.console.status("[bold green]Analyzing website report..."):
                report = await reporter.submit_website_report(
                    user_id=user_id,
                    url=url,
                    description=description or f"Reported website: {url}",
                    location=location
                )
        
        elif email:
            with ui.console.status("[bold green]Processing email report..."):
                with open(email, 'r', encoding='utf-8', errors='ignore') as f:
                    email_content = f.read()
                
                report = await reporter.submit_text_report(
                    user_id=user_id,
                    content=email_content,
                    source_info={'type': 'email', 'file': email, 'description': description},
                    location=location
                )
        
        if report:
            ui.print_success(f"Report submitted successfully! Report ID: {report.report_id}")
            ui.console.print(f"[bold]Scam Type:[/bold] {report.analysis_results.get('scam_type', 'unknown').title()}")
            ui.console.print(f"[bold]Confidence:[/bold] {report.confidence_score:.1%}")
            ui.console.print(f"[bold]Status:[/bold] {report.status.value.title()}")
            
            if location:
                ui.console.print(f"[bold]Location:[/bold] {location}")
            
            ui.console.print("\n[yellow]Your report will be reviewed by the community for verification.[/yellow]")
            ui.console.print("[cyan]Thank you for helping improve scam detection![/cyan]")
        
    except Exception as e:
        ui.print_error(f"Failed to submit report: {e}")


async def _run_heatmap_generation(days: int, output: Optional[str], trending: bool, ui):
    """Generate and display scam heatmap"""
    from .crowdsource import ScamHeatmap
    
    heatmap = ScamHeatmap()
    
    try:
        if trending:
            with ui.console.status("[bold green]Generating trending scams data..."):
                trending_data = await heatmap.get_trending_scams(days=days)
                global_stats = await heatmap.get_global_statistics()
            
            ui.console.print(f"\n[bold cyan]🔥 Trending Scams (Last {days} days)[/bold cyan]\n")
            
            if trending_data:
                from rich.table import Table
                from rich import box
                
                table = Table(
                    title="Trending Scam Activity",
                    border_style="cyan",
                    box=box.ROUNDED
                )
                table.add_column("Location", style="bold white")
                table.add_column("Scam Type", style="yellow")
                table.add_column("Reports", style="red", justify="center")
                table.add_column("Trend Score", style="green", justify="center")
                
                for trend in trending_data:
                    table.add_row(
                        trend['location'],
                        trend['scam_type'].title(),
                        str(trend['report_count']),
                        f"{trend['trend_score']:.1f}"
                    )
                
                ui.console.print(table)
            else:
                ui.console.print("[yellow]No trending scams found for the specified period.[/yellow]")
        
        else:
            with ui.console.status("[bold green]Generating heatmap data..."):
                heatmap_data = await heatmap.generate_heatmap_data(days=days)
                global_stats = await heatmap.get_global_statistics()
            
            # Display global statistics
            ui.console.print(f"\n[bold cyan]🌍 Global Scam Intelligence (Last {days} days)[/bold cyan]\n")
            
            from rich.panel import Panel
            stats_text = f"""
[bold]Total Reports:[/bold] {global_stats['total_reports']}
[bold]Verified Reports:[/bold] {global_stats['verified_reports']} ({global_stats['verification_rate']:.1f}%)
[bold]Last 24 Hours:[/bold] {global_stats['recent_24h']} reports

[bold]Top Regions:[/bold]
""" + "\n".join([f"• {region['region']}: {region['reports']} reports" for region in global_stats['top_regions'][:5]])
            
            stats_panel = Panel(stats_text, title="📊 Statistics", border_style="green")
            ui.console.print(stats_panel)
            
            # Display regional data
            if heatmap_data:
                from rich.table import Table
                from rich import box
                
                table = Table(
                    title="Regional Scam Activity",
                    border_style="cyan",
                    box=box.ROUNDED
                )
                table.add_column("Region", style="bold white")
                table.add_column("Risk Level", style="bold")
                table.add_column("Reports", style="cyan", justify="center")
                table.add_column("Verified", style="green", justify="center")
                table.add_column("Trend", style="yellow", justify="center")
                table.add_column("Top Scam Type", style="red")
                
                for region in heatmap_data[:15]:  # Show top 15 regions
                    risk_color = {
                        'critical': 'red',
                        'high': 'orange',
                        'medium': 'yellow',
                        'low': 'green'
                    }.get(region.risk_level, 'white')
                    
                    trend_icon = {
                        'increasing': '📈',
                        'decreasing': '📉',
                        'stable': '➡️'
                    }.get(region.trend_direction, '➡️')
                    
                    top_scam = max(region.scam_types.items(), key=lambda x: x[1])[0] if region.scam_types else 'N/A'
                    
                    table.add_row(
                        region.region,
                        f"[{risk_color}]{region.risk_level.upper()}[/{risk_color}]",
                        str(region.total_reports),
                        str(region.verified_reports),
                        f"{trend_icon} {region.trend_direction}",
                        top_scam.title()
                    )
                
                ui.console.print(table)
            
        # Generate HTML heatmap if requested
        if output:
            with ui.console.status("[bold green]Generating HTML heatmap..."):
                html_content = await heatmap.generate_heatmap_html(output)
            
            ui.print_success(f"Interactive heatmap saved to: {output}")
            ui.console.print("[cyan]Open the HTML file in your browser to view the interactive map.[/cyan]")
        
    except Exception as e:
        ui.print_error(f"Failed to generate heatmap: {e}")


async def _run_community_commands(stats: bool, validate: bool, reputation: Optional[str], ui):
    """Handle community validation commands"""
    from .crowdsource import CommunityValidator
    
    validator = CommunityValidator()
    
    try:
        if stats:
            with ui.console.status("[bold green]Loading community statistics..."):
                community_stats = validator.get_community_stats()
            
            ui.console.print("\n[bold cyan]👥 Community Statistics[/bold cyan]\n")
            
            from rich.table import Table
            from rich import box
            
            # Main stats table
            stats_table = Table(
                title="Community Overview",
                border_style="cyan",
                box=box.ROUNDED
            )
            stats_table.add_column("Metric", style="bold white")
            stats_table.add_column("Value", style="green")
            
            stats_table.add_row("Total Users", str(community_stats['total_users']))
            stats_table.add_row("Active Validators", str(community_stats['active_validators']))
            stats_table.add_row("Pending Reports", str(community_stats['pending_reports']))
            stats_table.add_row("Validated Reports", str(community_stats['validated_reports']))
            stats_table.add_row("Average User Reputation", f"{community_stats['avg_reputation']:.1f}")
            
            ui.console.print(stats_table)
            
            # Moderators table
            mod_table = Table(
                title="Moderator Levels",
                border_style="yellow",
                box=box.SIMPLE
            )
            mod_table.add_column("Level", style="bold")
            mod_table.add_column("Count", style="cyan")
            
            moderators = community_stats['moderators']
            mod_table.add_row("Junior Moderators", str(moderators['junior']))
            mod_table.add_row("Regular Moderators", str(moderators['regular']))
            mod_table.add_row("Senior Moderators", str(moderators['senior']))
            
            ui.console.print(mod_table)
            
            # Top contributors
            if community_stats['top_contributors']:
                contrib_table = Table(
                    title="Top Contributors",
                    border_style="green",
                    box=box.SIMPLE
                )
                contrib_table.add_column("User", style="bold")
                contrib_table.add_column("Trust Score", style="green")
                contrib_table.add_column("Verified Reports", style="cyan")
                contrib_table.add_column("Accurate Votes", style="yellow")
                
                for contrib in community_stats['top_contributors']:
                    contrib_table.add_row(
                        contrib['user_id'],
                        f"{contrib['trust_score']:.1f}",
                        str(contrib['reports_verified']),
                        str(contrib['accurate_votes'])
                    )
                
                ui.console.print(contrib_table)
        
        elif validate:
            # For demo purposes, use a sample user ID
            import uuid
            sample_user_id = str(uuid.uuid4())[:8]
            
            with ui.console.status("[bold green]Loading validation tasks..."):
                validation_tasks = validator.get_user_validation_tasks(sample_user_id)
            
            if validation_tasks:
                ui.console.print(f"\n[bold cyan]📋 Validation Tasks for User {sample_user_id}[/bold cyan]\n")
                
                from rich.table import Table
                from rich import box
                
                table = Table(
                    title="Pending Reports for Validation",
                    border_style="yellow",
                    box=box.ROUNDED
                )
                table.add_column("Report ID", style="bold white")
                table.add_column("Type", style="cyan")
                table.add_column("Content Preview", style="white")
                table.add_column("Confidence", style="green")
                table.add_column("Priority", style="red")
                
                for task in validation_tasks[:10]:
                    table.add_row(
                        task['report_id'][:8] + "...",
                        task['report_type'].title(),
                        task['content'][:50] + "..." if len(task['content']) > 50 else task['content'],
                        f"{task['confidence_score']:.1%}",
                        f"{task['priority_score']:.1f}"
                    )
                
                ui.console.print(table)
                ui.console.print("\n[yellow]Use the community validation interface to vote on these reports.[/yellow]")
            else:
                ui.console.print("[green]No validation tasks available at this time.[/green]")
        
        elif reputation:
            with ui.console.status(f"[bold green]Loading reputation for {reputation}..."):
                user_rep = validator.get_user_reputation(reputation)
            
            if user_rep:
                ui.console.print(f"\n[bold cyan]👤 User Reputation: {reputation}[/bold cyan]\n")
                
                from rich.panel import Panel
                
                rep_text = f"""
[bold]Trust Score:[/bold] {user_rep.trust_score:.1f}/20.0
[bold]Moderator Level:[/bold] {user_rep.moderator_level} ({['User', 'Junior Mod', 'Moderator', 'Senior Mod'][user_rep.moderator_level]})

[bold]Reports Submitted:[/bold] {user_rep.reports_submitted}
[bold]Reports Verified:[/bold] {user_rep.reports_verified}
[bold]Reports Rejected:[/bold] {user_rep.reports_rejected}

[bold]Votes Cast:[/bold] {user_rep.votes_cast}
[bold]Accurate Votes:[/bold] {user_rep.accurate_votes}
[bold]Voting Accuracy:[/bold] {user_rep.calculate_accuracy_rate():.1%}

[bold]Last Activity:[/bold] {user_rep.last_activity.strftime('%Y-%m-%d %H:%M')}
                """
                
                rep_panel = Panel(rep_text, title="User Reputation", border_style="green")
                ui.console.print(rep_panel)
            else:
                ui.console.print(f"[red]User {reputation} not found or has no reputation data.[/red]")
    
    except Exception as e:
        ui.print_error(f"Community command failed: {e}")
