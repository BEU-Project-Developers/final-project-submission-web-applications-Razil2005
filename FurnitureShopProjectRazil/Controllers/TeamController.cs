// Controllers/TeamController.cs
using FurnitureShopProjectRazil.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore; // Include metodu üçün
using System.Linq;
using System.Threading.Tasks;

namespace FurnitureShopProjectRazil.Controllers
{
    public class TeamController : Controller
    {
        private readonly AppDbContext _context;
        // ILogger istifadə etmək istəsəniz:
        // private readonly ILogger<TeamController> _logger;

        public TeamController(AppDbContext context /*, ILogger<TeamController> logger */)
        {
            _context = context;
            // _logger = logger;
        }

        // GET: Team
        public async Task<IActionResult> Index()
        {
            // Komanda üzvlərini çəkərkən onların Profession məlumatlarını da yükləyirik (Eager Loading)
            var teamMembers = await _context.Teams
                                      .Include(t => t.Profession)
                                      .ToListAsync();
            return View(teamMembers);
        }

       
    }
}