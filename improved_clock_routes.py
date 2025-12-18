# Add these imports at the top if not already there
from sqlalchemy import func

# Replace the clock_history route with these three routes:

@app.route('/clock/history')
@login_required
def clock_history():
    """
    For admins: Shows summary of all users with total hours
    For regular users: Shows their own history
    """
    if current_user.role == 'admin':
        # Admin view - show summary of all users
        users_summary = db.session.query(
            User.id,
            User.username,
            User.role,
            func.sum(TimeEntry.total_hours).label('total_hours'),
            func.count(TimeEntry.id).label('total_entries')
        ).outerjoin(TimeEntry).group_by(User.id).all()
        
        return render_template('clock_summary.html', users_summary=users_summary)
    else:
        # Regular user view - show their own history
        page = request.args.get('page', 1, type=int)
        pagination = TimeEntry.query.filter_by(user_id=current_user.id).order_by(
            TimeEntry.clock_in.desc()
        ).paginate(page=page, per_page=25, error_out=False)
        
        return render_template('clock_history.html', pagination=pagination)

@app.route('/clock/user/<int:user_id>')
@login_required
def clock_user_detail(user_id):
    """
    Admin only: View detailed time entries for a specific user
    """
    if current_user.role != 'admin':
        flash('Access denied. Administrators only.', 'error')
        return redirect(url_for('clock_history'))
    
    user = User.query.get_or_404(user_id)
    page = request.args.get('page', 1, type=int)
    
    # Get pagination for this user's entries
    pagination = TimeEntry.query.filter_by(user_id=user_id).order_by(
        TimeEntry.clock_in.desc()
    ).paginate(page=page, per_page=25, error_out=False)
    
    # Calculate total hours for this user
    total_hours = db.session.query(
        func.sum(TimeEntry.total_hours)
    ).filter_by(user_id=user_id).scalar() or 0
    
    return render_template('clock_user_detail.html', 
                         user=user, 
                         pagination=pagination,
                         total_hours=total_hours)