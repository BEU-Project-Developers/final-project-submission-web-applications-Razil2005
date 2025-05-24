using Microsoft.AspNetCore.Mvc;

namespace FurnitureShopProjectRazil.Controllers
{
    public class ShopController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
