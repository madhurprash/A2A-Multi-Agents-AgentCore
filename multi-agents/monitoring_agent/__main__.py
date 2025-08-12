#!/usr/bin/env python3
"""
Entry point for running the monitoring agent as a module.
This allows running: python -m monitoring_agent
"""

if __name__ == "__main__":
    # Import and run the monitoring agent's main logic
    from monitoring_agent import parse_arguments, logger, interactive_cli, app
    
    args = parse_arguments()
    logger.info(f"Arguments: {args}")
    session_id = args.session_id

    if args.interactive:
        interactive_cli(session_id)
    else:
        app.run()