using Microsoft.AspNetCore.Mvc;

namespace FurnitureShopProjectRazil.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
